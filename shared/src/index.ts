// ============================================
// VaultGuard - Shared Type Definitions
// ============================================

// --- Vault Entry Types ---

export interface PasswordEntry {
  id: string;
  title: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
  category?: string;
  favicon?: string;
  createdAt: number;
  updatedAt: number;
}

export interface TwoFactorEntry {
  id: string;
  title: string;
  issuer?: string;
  account?: string;
  secret: string; // Base32 (or hex) encoded OTP secret
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  digits?: number;
  period?: number;
  counter?: number; // For HOTP
  type: 'TOTP' | 'HOTP';
  uri?: string; // otpauth:// URI
  /** Secret encoding when it is not standard base32. */
  encoding?: 'base32' | 'hex' | 'ascii';
  /** Steam Guard entries use a 5-character alphabet instead of digits. */
  steam?: boolean;
  /** Pinned entries sort to the top of the list. */
  pinned?: boolean;
  /** Manual sort position within the list. */
  order?: number;
  /** Optional free-form note shown on the card's detail view. */
  notes?: string;
  /** Domains this entry belongs to, used for page matching in the extension. */
  domains?: string[];
  /** Last time a code was copied/filled — drives "recently used" sorting. */
  lastUsedAt?: number;
  createdAt: number;
  updatedAt: number;
}

/** A generated code plus the countdown metadata the UI needs to render it. */
export interface OtpCodeResult {
  id: string;
  code: string;
  nextCode?: string;
  counter: number;
  period: number;
  digits: number;
  remainingSeconds: number;
  expiresAt: number;
  error?: string;
}

export interface VaultData {
  passwords: PasswordEntry[];
  twoFactor: TwoFactorEntry[];
}

// --- Auth Types ---

export interface AuthConfig {
  masterPasswordHash: string; // PBKDF2 hash
  salt: string; // Hex encoded
  iterations: number;
  createdAt: number;
  lastLogin?: number;
  autoLockMinutes: number;
}

export interface UnlockRequest {
  masterPassword: string;
}

export interface UnlockResponse {
  success: boolean;
  sessionToken?: string;
  error?: string;
}

// --- Crypto Types ---

export interface EncryptionResult {
  ciphertext: string; // Base64 encoded
  iv: string; // Hex encoded
  tag?: string; // Hex encoded (for GCM)
}

export interface DerivedKey {
  key: string; // Hex encoded
  salt: string; // Hex encoded
}

// --- Native Messaging Types (Extension <-> Desktop) ---

export type MessageType =
  | 'AUTH_STATUS'
  | 'GET_PASSWORDS'
  | 'GET_TOTP'
  | 'AUTO_FILL'
  | 'AUTO_FILL_TOTP'
  | 'SAVE_PASSWORD'
  | 'SAVE_TOTP'
  | 'GENERATE_TOTP'
  | 'GENERATE_TOTP_BATCH'
  | 'INCREMENT_HOTP'
  | 'VERIFY_TOTP'
  | 'UNLOCK_VAULT'
  | 'LOCK_VAULT'
  | 'SCAN_PAGE'
  | 'GET_ENTRIES_FOR_URL'
  | 'GET_BIOMETRIC_STATUS'
  | 'BIOMETRIC_UNLOCK'
  | 'BIOMETRIC_REGISTER'
  | 'SHOW_WINDOW'
  /** Sync: pull full vault state for the extension's local mirror. */
  | 'SYNC_PULL'
  /** Sync: push extension changes (creates/updates/deletes) into the vault. */
  | 'SYNC_PUSH'
  /** Handshake: the extension sends this first and expects HELLO back. */
  | 'HELLO'
  /** Cheap liveness probe used by the extension's health check. */
  | 'PING'
  | 'PONG'
  | 'RESPONSE'
  | 'ERROR';

export interface NativeMessage {
  type: MessageType;
  payload?: any;
  requestId?: string;
  error?: string;
}

export interface PageFieldInfo {
  type: 'username' | 'password' | 'totp' | 'email' | 'text';
  selector: string;
  value?: string;
  placeholder?: string;
  autocomplete?: string;
  name?: string;
  id?: string;
}

export interface ScanResult {
  url: string;
  title: string;
  fields: PageFieldInfo[];
  hasLoginForm: boolean;
  hasTotpField: boolean;
  matchingPasswordEntries: PasswordEntry[];
  matchingTotpEntries: TwoFactorEntry[];
}

// --- App Settings ---

export interface AppSettings {
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  autoFillOnPageLoad: boolean;
  showNotifications: boolean;
  theme: 'light' | 'dark' | 'system';
  language: string;
  minimizeToTray: boolean;
  startWithWindows: boolean;
  biometricEnabled: boolean;
}

export interface BackupSettings {
  enabled: boolean;
  intervalMinutes: number;
  backupPath: string;
  maxBackups: number;
  encrypted: boolean;
}

export interface BackupEntry {
  filename: string;
  timestamp: number;
  size: number;
}

// --- Biometric Types ---

export interface BiometricCredential {
  credentialId: string;
  authenticatorData: string;
  signCount: number;
  createdAt: number;
}

export interface BiometricConfig {
  enabled: boolean;
  credentialId?: string;
  authenticatorData?: string;
  createdAt?: number;
}

// --- CSV Import/Export Types ---

export interface CSVImportResult {
  success: boolean;
  entries?: PasswordEntry[];
  errors?: string[];
  warnings?: string[];
  totalRows?: number;
}

// --- IPC Event Names ---

export const IPC_CHANNELS = {
  // Auth
  AUTH_STATUS: 'auth:status',
  SETUP_MASTER: 'auth:setup',
  UNLOCK: 'auth:unlock',
  LOCK: 'auth:lock',
  CHANGE_PASSWORD: 'auth:change-password',

  // Vault
  GET_PASSWORDS: 'vault:get-passwords',
  ADD_PASSWORD: 'vault:add-password',
  UPDATE_PASSWORD: 'vault:update-password',
  DELETE_PASSWORD: 'vault:delete-password',
  SEARCH_PASSWORDS: 'vault:search-passwords',

  // 2FA
  GET_TOTP_ENTRIES: 'vault:get-totp',
  ADD_TOTP: 'vault:add-totp',
  UPDATE_TOTP: 'vault:update-totp',
  DELETE_TOTP: 'vault:delete-totp',
  GENERATE_TOTP: 'vault:generate-totp',
  /** Generate codes for many entries in one round-trip (see OtpCodeResult). */
  GENERATE_TOTP_BATCH: 'vault:generate-totp-batch',
  VERIFY_TOTP: 'vault:verify-totp',
  GENERATE_SECRET: 'vault:generate-secret',
  GET_OTPAUTH_URI: 'vault:get-otpauth-uri',
  /** Advance an HOTP counter and return the new code. */
  INCREMENT_HOTP: 'vault:increment-hotp',
  /** Import otpauth:// / otpauth-migration:// URIs (accepts many lines). */
  IMPORT_OTP_URIS: 'vault:import-otp-uris',
  /** Persist a new manual ordering for the 2FA list. */
  REORDER_TOTP: 'vault:reorder-totp',
  /** Render an entry's otpauth URI as a QR-code data URL. */
  GET_TOTP_QR: 'vault:get-totp-qr',
  /** Validate a secret without saving it. */
  VALIDATE_SECRET: 'vault:validate-secret',

  // Settings
  GET_SETTINGS: 'settings:get',
  UPDATE_SETTINGS: 'settings:update',

  // Export/Import
  EXPORT_VAULT: 'vault:export',
  IMPORT_VAULT: 'vault:import',
  EXPORT_CSV: 'vault:export-csv',
  IMPORT_CSV: 'vault:import-csv',
  VALIDATE_CSV: 'vault:validate-csv',

  // Biometric
  BIOMETRIC_STATUS: 'biometric:status',
  BIOMETRIC_REGISTER: 'biometric:register',
  BIOMETRIC_AUTHENTICATE: 'biometric:authenticate',
  BIOMETRIC_DISABLE: 'biometric:disable',

  // Backup
  GET_BACKUP_SETTINGS: 'backup:get-settings',
  UPDATE_BACKUP_SETTINGS: 'backup:update-settings',
  CREATE_BACKUP: 'backup:create',
  RESTORE_BACKUP: 'backup:restore',
  DELETE_BACKUP: 'backup:delete',
  GET_BACKUP_LIST: 'backup:list',
  SELECT_BACKUP_FOLDER: 'backup:select-folder',

  // Tray
  TRAY_LOCK: 'tray:lock',
  TRAY_QUIT: 'tray:quit',

  // Window controls (the frameless title bar drives these)
  WINDOW_MINIMIZE: 'window:minimize',
  WINDOW_MAXIMIZE: 'window:maximize',
  WINDOW_CLOSE: 'window:close',
  WINDOW_IS_MAXIMIZED: 'window:is-maximized',
  WINDOW_STATE_CHANGED: 'window:state-changed',

  // Extension bridge diagnostics (shown in Settings)
  BRIDGE_STATUS: 'bridge:status',
  BRIDGE_REGISTER: 'bridge:register-host',

  // Native Messaging (for extension)
  NATIVE_MSG: 'native:message',
} as const;

/** Diagnostics for the desktop <-> extension bridge, surfaced in Settings. */
export interface BridgeStatus {
  httpPort: number | null;
  httpRunning: boolean;
  nativeHostInstalled: boolean;
  nativeHostManifestPath: string | null;
  registeredBrowsers: string[];
  registrationErrors: string[];
  connectedExtensions: number;
  lastExtensionSeenAt: number | null;
}

// --- Utility Types ---

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export interface SearchResult {
  passwords: PasswordEntry[];
  totpEntries: TwoFactorEntry[];
}

// --- Extension Types ---

export interface ExtensionState {
  isDesktopConnected: boolean;
  isVaultUnlocked: boolean;
  currentPageInfo: ScanResult | null;
}

export interface PasswordFormData {
  title: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
  category?: string;
}

export interface TotpFormData {
  title: string;
  issuer?: string;
  account?: string;
  secret: string;
  type: 'TOTP' | 'HOTP';
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  digits?: number;
  period?: number;
}
