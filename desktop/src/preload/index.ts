// ============================================
// VaultGuard - Electron Preload Script
// Secure IPC bridge between main and renderer
// ============================================

import { contextBridge, ipcRenderer, IpcRendererEvent } from 'electron';
import {
  IPC_CHANNELS,
  PasswordEntry,
  TwoFactorEntry,
  AppSettings,
  BackupSettings,
  OtpCodeResult,
  BridgeStatus,
} from '@vaultguard/shared';

/** Subscribe to a main-process push and return an unsubscribe function. */
function subscribe<T>(channel: string, callback: (payload: T) => void): () => void {
  const handler = (_event: IpcRendererEvent, payload: T) => callback(payload);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
}

// Expose a secure API to the renderer process
contextBridge.exposeInMainWorld('vaultAPI', {
  // --- Auth ---
  getAuthStatus: () => ipcRenderer.invoke(IPC_CHANNELS.AUTH_STATUS),
  setupMasterPassword: (data: { password: string; biometricCredentialId?: string; biometricAuthenticatorData?: string }) =>
    ipcRenderer.invoke(IPC_CHANNELS.SETUP_MASTER, data),
  unlock: (password: string) =>
    ipcRenderer.invoke(IPC_CHANNELS.UNLOCK, password),
  lock: () => ipcRenderer.invoke(IPC_CHANNELS.LOCK),
  changePassword: (currentPassword: string, newPassword: string) =>
    ipcRenderer.invoke(IPC_CHANNELS.CHANGE_PASSWORD, { currentPassword, newPassword }),

  // --- Passwords ---
  getPasswords: () => ipcRenderer.invoke(IPC_CHANNELS.GET_PASSWORDS),
  addPassword: (entry: Omit<PasswordEntry, 'id' | 'createdAt' | 'updatedAt'>) =>
    ipcRenderer.invoke(IPC_CHANNELS.ADD_PASSWORD, entry),
  updatePassword: (id: string, updates: Partial<PasswordEntry>) =>
    ipcRenderer.invoke(IPC_CHANNELS.UPDATE_PASSWORD, { id, updates }),
  deletePassword: (id: string) =>
    ipcRenderer.invoke(IPC_CHANNELS.DELETE_PASSWORD, id),
  searchPasswords: (query: string) =>
    ipcRenderer.invoke(IPC_CHANNELS.SEARCH_PASSWORDS, query),

  // --- TOTP ---
  getTotpEntries: () => ipcRenderer.invoke(IPC_CHANNELS.GET_TOTP_ENTRIES),
  addTotpEntry: (entry: Omit<TwoFactorEntry, 'id' | 'createdAt' | 'updatedAt'>) =>
    ipcRenderer.invoke(IPC_CHANNELS.ADD_TOTP, entry),
  updateTotpEntry: (id: string, updates: Partial<TwoFactorEntry>) =>
    ipcRenderer.invoke(IPC_CHANNELS.UPDATE_TOTP, { id, updates }),
  deleteTotpEntry: (id: string) =>
    ipcRenderer.invoke(IPC_CHANNELS.DELETE_TOTP, id),
  generateTotp: (secret: string, options?: Record<string, unknown>) =>
    ipcRenderer.invoke(IPC_CHANNELS.GENERATE_TOTP, { secret, options }),
  /**
   * Codes for the whole list in one call. The vault grid used to invoke
   * `generateTotp` once per card per second; batching is what makes the
   * countdown smooth instead of stuttery.
   */
  generateTotpBatch: (payload?: { ids?: string[]; timestamp?: number; withNext?: boolean }) =>
    ipcRenderer.invoke(IPC_CHANNELS.GENERATE_TOTP_BATCH, payload),
  verifyTotp: (token: string, secret: string, options?: Record<string, unknown>) =>
    ipcRenderer.invoke(IPC_CHANNELS.VERIFY_TOTP, { token, secret, options }),
  generateSecret: () => ipcRenderer.invoke(IPC_CHANNELS.GENERATE_SECRET),
  getOtpauthUri: (data: { account: string; issuer: string; secret: string; options?: Record<string, unknown> }) =>
    ipcRenderer.invoke(IPC_CHANNELS.GET_OTPAUTH_URI, data),
  incrementHotp: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.INCREMENT_HOTP, id),
  importOtpUris: (input: string) => ipcRenderer.invoke(IPC_CHANNELS.IMPORT_OTP_URIS, input),
  reorderTotpEntries: (orderedIds: string[]) =>
    ipcRenderer.invoke(IPC_CHANNELS.REORDER_TOTP, orderedIds),
  getTotpQr: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.GET_TOTP_QR, id),
  validateSecret: (secret: string, encoding?: string) =>
    ipcRenderer.invoke(IPC_CHANNELS.VALIDATE_SECRET, { secret, encoding }),

  // --- Settings ---
  getSettings: () => ipcRenderer.invoke(IPC_CHANNELS.GET_SETTINGS),
  updateSettings: (settings: Partial<AppSettings>) =>
    ipcRenderer.invoke(IPC_CHANNELS.UPDATE_SETTINGS, settings),

  // --- Export/Import ---
  exportVault: () => ipcRenderer.invoke(IPC_CHANNELS.EXPORT_VAULT),
  importVault: () => ipcRenderer.invoke(IPC_CHANNELS.IMPORT_VAULT),
  exportCSV: () => ipcRenderer.invoke(IPC_CHANNELS.EXPORT_CSV),
  importCSV: () => ipcRenderer.invoke(IPC_CHANNELS.IMPORT_CSV),
  validateCSV: (csvContent: string) => ipcRenderer.invoke(IPC_CHANNELS.VALIDATE_CSV, csvContent),

  // --- Biometric ---
  getBiometricStatus: () => ipcRenderer.invoke(IPC_CHANNELS.BIOMETRIC_STATUS),
  registerBiometric: (data: { credentialId: string; authenticatorData: string }) =>
    ipcRenderer.invoke(IPC_CHANNELS.BIOMETRIC_REGISTER, data),
  authenticateBiometric: (data: { credentialId: string }) =>
    ipcRenderer.invoke(IPC_CHANNELS.BIOMETRIC_AUTHENTICATE, data),
  disableBiometric: () => ipcRenderer.invoke(IPC_CHANNELS.BIOMETRIC_DISABLE),

  // --- Backup ---
  getBackupSettings: () => ipcRenderer.invoke(IPC_CHANNELS.GET_BACKUP_SETTINGS),
  updateBackupSettings: (settings: Partial<BackupSettings>) =>
    ipcRenderer.invoke(IPC_CHANNELS.UPDATE_BACKUP_SETTINGS, settings),
  createBackup: () => ipcRenderer.invoke(IPC_CHANNELS.CREATE_BACKUP),
  restoreBackup: (filename: string) => ipcRenderer.invoke(IPC_CHANNELS.RESTORE_BACKUP, filename),
  deleteBackup: (filename: string) => ipcRenderer.invoke(IPC_CHANNELS.DELETE_BACKUP, filename),
  getBackupList: () => ipcRenderer.invoke(IPC_CHANNELS.GET_BACKUP_LIST),
  selectBackupFolder: () => ipcRenderer.invoke(IPC_CHANNELS.SELECT_BACKUP_FOLDER),

  // --- Clipboard ---
  copyToClipboard: (text: string) => ipcRenderer.invoke('clipboard:copy', text),

  // --- Window controls (the renderer draws its own title bar) ---
  minimizeWindow: () => ipcRenderer.invoke(IPC_CHANNELS.WINDOW_MINIMIZE),
  toggleMaximizeWindow: () => ipcRenderer.invoke(IPC_CHANNELS.WINDOW_MAXIMIZE),
  closeWindow: () => ipcRenderer.invoke(IPC_CHANNELS.WINDOW_CLOSE),
  isWindowMaximized: () => ipcRenderer.invoke(IPC_CHANNELS.WINDOW_IS_MAXIMIZED),
  platform: process.platform,

  // --- Extension bridge ---
  getBridgeStatus: () => ipcRenderer.invoke(IPC_CHANNELS.BRIDGE_STATUS),
  registerNativeHost: () => ipcRenderer.invoke(IPC_CHANNELS.BRIDGE_REGISTER),
  respondToPairing: (approved: boolean) => ipcRenderer.invoke('bridge:pairing-response', approved),
  setExtensionId: (extensionId: string) => ipcRenderer.invoke('extension:set-id', extensionId),

  // --- Tray ---
  trayLock: () => ipcRenderer.invoke(IPC_CHANNELS.TRAY_LOCK),
  trayQuit: () => ipcRenderer.invoke(IPC_CHANNELS.TRAY_QUIT),

  // --- Event Listeners ---
  onVaultLocked: (callback: () => void) => subscribe('vault:locked', callback),
  onVaultAutoLocked: (callback: () => void) => subscribe('vault:auto-locked', callback),
  /** Fired when the extension unlocked the vault, so the UI can catch up. */
  onVaultUnlockedRemotely: (callback: () => void) => subscribe('vault:unlocked-remotely', callback),
  /** Fired after any write, including writes made by the extension. */
  onVaultChanged: (callback: (payload: { epoch: number }) => void) =>
    subscribe('vault:changed', callback),
  onWindowStateChanged: (callback: (state: { maximized: boolean; fullScreen: boolean }) => void) =>
    subscribe(IPC_CHANNELS.WINDOW_STATE_CHANGED, callback),
  onBridgeStatusChanged: (callback: (status: BridgeStatus) => void) =>
    subscribe('bridge:status-changed', callback),
  /** An extension is asking to pair over the loopback bridge. */
  onPairingRequest: (
    callback: (req: { code: string; extensionId: string; browser: string; expiresAt: number }) => void
  ) => subscribe('bridge:pairing-request', callback),
  onBackupCreated: (callback: (payload: { filename: string }) => void) =>
    subscribe('backup:created', callback),
});

// TypeScript type declaration
export interface VaultAPI {
  getAuthStatus: () => Promise<{ hasAuthConfig: boolean; isUnlocked: boolean }>;
  setupMasterPassword: (data: { password: string; biometricCredentialId?: string; biometricAuthenticatorData?: string }) => Promise<{ success: boolean; sessionToken?: string }>;
  unlock: (password: string) => Promise<{ success: boolean; sessionToken?: string; error?: string }>;
  lock: () => Promise<{ success: boolean }>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>;

  getPasswords: () => Promise<PasswordEntry[]>;
  addPassword: (entry: Omit<PasswordEntry, 'id' | 'createdAt' | 'updatedAt'>) => Promise<PasswordEntry>;
  updatePassword: (id: string, updates: Partial<PasswordEntry>) => Promise<PasswordEntry | null>;
  deletePassword: (id: string) => Promise<boolean>;
  searchPasswords: (query: string) => Promise<PasswordEntry[]>;

  getTotpEntries: () => Promise<TwoFactorEntry[]>;
  addTotpEntry: (entry: Omit<TwoFactorEntry, 'id' | 'createdAt' | 'updatedAt'>) => Promise<TwoFactorEntry>;
  updateTotpEntry: (id: string, updates: Partial<TwoFactorEntry>) => Promise<TwoFactorEntry | null>;
  deleteTotpEntry: (id: string) => Promise<boolean>;
  generateTotp: (secret: string, options?: Record<string, unknown>) => Promise<string>;
  generateTotpBatch: (payload?: { ids?: string[]; timestamp?: number; withNext?: boolean }) => Promise<OtpCodeResult[]>;
  verifyTotp: (token: string, secret: string, options?: Record<string, unknown>) => Promise<boolean>;
  generateSecret: () => Promise<string>;
  getOtpauthUri: (data: { account: string; issuer: string; secret: string; options?: Record<string, unknown> }) => Promise<string>;
  incrementHotp: (id: string) => Promise<OtpCodeResult>;
  importOtpUris: (input: string) => Promise<{
    success: boolean;
    imported: number;
    skipped: number;
    errors: string[];
    entries: TwoFactorEntry[];
  }>;
  reorderTotpEntries: (orderedIds: string[]) => Promise<TwoFactorEntry[]>;
  getTotpQr: (id: string) => Promise<{ uri: string; dataUrl: string }>;
  validateSecret: (secret: string, encoding?: string) => Promise<{ valid: boolean; error?: string; keyBytes?: number }>;

  getSettings: () => Promise<AppSettings>;
  updateSettings: (settings: Partial<AppSettings>) => Promise<AppSettings>;

  exportVault: () => Promise<{ success?: boolean; path?: string; canceled?: boolean; error?: string }>;
  importVault: () => Promise<{ success?: boolean; canceled?: boolean; error?: string }>;
  exportCSV: () => Promise<{ success?: boolean; path?: string; canceled?: boolean; count?: number; error?: string }>;
  importCSV: () => Promise<{ success?: boolean; canceled?: boolean; count?: number; duplicatesSkipped?: number; errors?: string[]; warnings?: string[]; error?: string }>;
  validateCSV: (csvContent: string) => Promise<{ valid: boolean; errors: string[]; warnings: string[] }>;

  // --- Biometric ---
  getBiometricStatus: () => Promise<{ enabled: boolean; credentialId?: string; hasConfig: boolean }>;
  registerBiometric: (data: { credentialId: string; authenticatorData: string }) => Promise<{ success: boolean; error?: string }>;
  authenticateBiometric: (data: { credentialId: string }) => Promise<{ success: boolean; sessionToken?: string; error?: string }>;
  disableBiometric: () => Promise<{ success: boolean; error?: string }>;

  // --- Backup ---
  getBackupSettings: () => Promise<BackupSettings>;
  updateBackupSettings: (settings: Partial<BackupSettings>) => Promise<BackupSettings>;
  createBackup: () => Promise<{ success?: boolean; filename?: string; path?: string; error?: string }>;
  restoreBackup: (filename: string) => Promise<{ success?: boolean; error?: string }>;
  deleteBackup: (filename: string) => Promise<{ success?: boolean; error?: string }>;
  getBackupList: () => Promise<Array<{ filename: string; timestamp: number; size: number }>>;
  selectBackupFolder: () => Promise<{ success?: boolean; path?: string; canceled?: boolean }>;

  copyToClipboard: (text: string) => Promise<{ success: boolean }>;

  // --- Window controls ---
  minimizeWindow: () => Promise<void>;
  toggleMaximizeWindow: () => Promise<boolean>;
  closeWindow: () => Promise<void>;
  isWindowMaximized: () => Promise<boolean>;
  platform: NodeJS.Platform;

  // --- Extension bridge ---
  getBridgeStatus: () => Promise<BridgeStatus>;
  registerNativeHost: () => Promise<BridgeStatus>;
  respondToPairing: (approved: boolean) => Promise<{ success: boolean; approved: boolean }>;
  setExtensionId: (extensionId: string) => Promise<{ success: boolean; error?: string }>;

  trayLock: () => Promise<void>;
  trayQuit: () => Promise<void>;

  onVaultLocked: (callback: () => void) => () => void;
  onVaultAutoLocked: (callback: () => void) => () => void;
  onVaultUnlockedRemotely: (callback: () => void) => () => void;
  onVaultChanged: (callback: (payload: { epoch: number }) => void) => () => void;
  onWindowStateChanged: (callback: (state: { maximized: boolean; fullScreen: boolean }) => void) => () => void;
  onBridgeStatusChanged: (callback: (status: BridgeStatus) => void) => () => void;
  onPairingRequest: (
    callback: (req: { code: string; extensionId: string; browser: string; expiresAt: number }) => void
  ) => () => void;
  onBackupCreated: (callback: (payload: { filename: string }) => void) => () => void;
}

declare global {
  interface Window {
    vaultAPI: VaultAPI;
  }
}
