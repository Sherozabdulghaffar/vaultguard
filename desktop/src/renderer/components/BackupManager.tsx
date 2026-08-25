import React, { useState, useEffect } from 'react';

interface BackupSettings {
  enabled: boolean;
  intervalMinutes: number;
  backupPath: string;
  maxBackups: number;
  encrypted: boolean;
}

interface BackupEntry {
  filename: string;
  timestamp: number;
  size: number;
}

export default function BackupManager() {
  const [settings, setSettings] = useState<BackupSettings>({
    enabled: false,
    intervalMinutes: 60,
    backupPath: '',
    maxBackups: 10,
    encrypted: true,
  });
  const [backups, setBackups] = useState<BackupEntry[]>([]);
  const [isBackingUp, setIsBackingUp] = useState(false);
  const [lastBackup, setLastBackup] = useState<number | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    loadSettings();
    loadBackups();
  }, []);

  const loadSettings = async () => {
    try {
      const result = await window.vaultAPI.getBackupSettings();
      if (result) setSettings(result);
    } catch (err) {
      console.error('Failed to load backup settings:', err);
    }
  };

  const loadBackups = async () => {
    try {
      const result = await window.vaultAPI.getBackupList();
      if (Array.isArray(result)) {
        setBackups(result);
        if (result.length > 0) {
          setLastBackup(result[0].timestamp);
        }
      }
    } catch (err) {
      console.error('Failed to load backups:', err);
    }
  };

  const saveSettings = async (newSettings: BackupSettings) => {
    setSettings(newSettings);
    try {
      await window.vaultAPI.updateBackupSettings(newSettings);
      showNotification('success', 'Backup settings saved');
    } catch (err) {
      showNotification('error', 'Failed to save backup settings');
    }
  };

  const selectBackupPath = async () => {
    try {
      const result = await window.vaultAPI.selectBackupFolder();
      if (result && !result.canceled && result.path) {
        saveSettings({ ...settings, backupPath: result.path });
      }
    } catch (err) {
      showNotification('error', 'Failed to select backup folder');
    }
  };

  const createBackup = async () => {
    setIsBackingUp(true);
    try {
      const result = await window.vaultAPI.createBackup();
      if (result.success) {
        showNotification('success', `Backup created: ${result.filename}`);
        loadBackups();
      } else {
        showNotification('error', result.error || 'Backup failed');
      }
    } catch (err) {
      showNotification('error', 'Backup failed');
    } finally {
      setIsBackingUp(false);
    }
  };

  const restoreBackup = async (filename: string) => {
    if (!confirm(`Are you sure you want to restore from ${filename}? This will replace your current vault data.`)) {
      return;
    }

    try {
      const result = await window.vaultAPI.restoreBackup(filename);
      if (result.success) {
        showNotification('success', 'Vault restored successfully');
      } else {
        showNotification('error', result.error || 'Restore failed');
      }
    } catch (err) {
      showNotification('error', 'Restore failed');
    }
  };

  const deleteBackup = async (filename: string) => {
    if (!confirm(`Are you sure you want to delete ${filename}?`)) {
      return;
    }

    try {
      const result = await window.vaultAPI.deleteBackup(filename);
      if (result.success) {
        loadBackups();
        showNotification('success', 'Backup deleted');
      }
    } catch (err) {
      showNotification('error', 'Failed to delete backup');
    }
  };

  const showNotification = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 3000);
  };

  const formatTimestamp = (ts: number) => {
    return new Date(ts).toLocaleString();
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const getTimeSinceLastBackup = () => {
    if (!lastBackup) return 'Never';
    const diff = Date.now() - lastBackup;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    return `${minutes}m ago`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Backup Manager</h1>
        <p className="text-gray-400 text-sm mt-1">Automatic encrypted backups of your vault</p>
      </div>

      {/* Backup Status Card */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-green-500/20 to-green-600/20 flex items-center justify-center">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-green-400">
                <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                <polyline points="17 21 17 13 7 13 7 21"/>
                <polyline points="7 3 7 8 15 8"/>
              </svg>
            </div>
            <div>
              <h3 className="font-semibold">Last Backup</h3>
              <p className="text-sm text-gray-400">{getTimeSinceLastBackup()}</p>
            </div>
          </div>
          <button
            onClick={createBackup}
            disabled={isBackingUp}
            className="btn-primary flex items-center gap-2"
          >
            {isBackingUp ? (
              <>
                <div className="spinner w-4 h-4 border-2" />
                Backing up...
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 5v14M5 12h14"/>
                </svg>
                Create Backup Now
              </>
            )}
          </button>
        </div>
      </div>

      {/* Backup Settings */}
      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4">Backup Settings</h2>

        {/* Enable/Disable */}
        <div className="flex items-center justify-between py-3 border-b border-dark-border">
          <div>
            <p className="text-sm font-medium">Automatic Backups</p>
            <p className="text-xs text-gray-400">Create backups automatically on a schedule</p>
          </div>
          <button
            onClick={() => saveSettings({ ...settings, enabled: !settings.enabled })}
            className={`relative w-11 h-6 rounded-full transition-colors ${settings.enabled ? 'bg-vault-500' : 'bg-dark-border'}`}
          >
            <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${settings.enabled ? 'left-6' : 'left-1'}`}/>
          </button>
        </div>

        {/* Interval */}
        <div className="flex items-center justify-between py-3 border-b border-dark-border">
          <div>
            <p className="text-sm font-medium">Backup Interval</p>
            <p className="text-xs text-gray-400">How often to create automatic backups</p>
          </div>
          <select
            value={settings.intervalMinutes}
            onChange={(e) => saveSettings({ ...settings, intervalMinutes: parseInt(e.target.value) })}
            className="input-field w-32"
            disabled={!settings.enabled}
          >
            <option value="15">Every 15 min</option>
            <option value="30">Every 30 min</option>
            <option value="60">Every hour</option>
            <option value="360">Every 6 hours</option>
            <option value="720">Every 12 hours</option>
            <option value="1440">Daily</option>
          </select>
        </div>

        {/* Backup Location */}
        <div className="flex items-center justify-between py-3 border-b border-dark-border">
          <div className="flex-1 mr-4">
            <p className="text-sm font-medium">Backup Location</p>
            <p className="text-xs text-gray-400 truncate">
              {settings.backupPath || 'Not set (using default)'}
            </p>
          </div>
          <button onClick={selectBackupPath} className="btn-secondary text-sm">
            Browse
          </button>
        </div>

        {/* Max Backups */}
        <div className="flex items-center justify-between py-3 border-b border-dark-border">
          <div>
            <p className="text-sm font-medium">Keep Backups</p>
            <p className="text-xs text-gray-400">Maximum number of backups to keep</p>
          </div>
          <select
            value={settings.maxBackups}
            onChange={(e) => saveSettings({ ...settings, maxBackups: parseInt(e.target.value) })}
            className="input-field w-24"
          >
            <option value="5">5</option>
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="0">Unlimited</option>
          </select>
        </div>

        {/* Encryption */}
        <div className="flex items-center justify-between py-3">
          <div>
            <p className="text-sm font-medium">Encrypt Backups</p>
            <p className="text-xs text-gray-400">Use AES-256 encryption for backup files</p>
          </div>
          <button
            onClick={() => saveSettings({ ...settings, encrypted: !settings.encrypted })}
            className={`relative w-11 h-6 rounded-full transition-colors ${settings.encrypted ? 'bg-vault-500' : 'bg-dark-border'}`}
          >
            <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${settings.encrypted ? 'left-6' : 'left-1'}`}/>
          </button>
        </div>
      </div>

      {/* Backup History */}
      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4">Backup History</h2>

        {backups.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mx-auto mb-4 opacity-50">
              <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
              <polyline points="17 21 17 13 7 13 7 21"/>
            </svg>
            <p>No backups yet</p>
            <p className="text-sm mt-1">Create your first backup to get started</p>
          </div>
        ) : (
          <div className="space-y-2">
            {backups.map((backup, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-dark-bg/30 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-vault-500/10 flex items-center justify-center">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-vault-400">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                      <polyline points="14 2 14 8 20 8"/>
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm font-medium">{backup.filename}</p>
                    <p className="text-xs text-gray-400">
                      {formatTimestamp(backup.timestamp)} • {formatSize(backup.size)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => restoreBackup(backup.filename)}
                    className="p-2 rounded-lg hover:bg-vault-500/20 text-gray-400 hover:text-vault-400 transition-all"
                    title="Restore"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="1 4 1 10 7 10"/>
                      <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
                    </svg>
                  </button>
                  <button
                    onClick={() => deleteBackup(backup.filename)}
                    className="p-2 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-all"
                    title="Delete"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="3 6 5 6 21 6"/>
                      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                    </svg>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

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
