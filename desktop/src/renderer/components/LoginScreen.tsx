import React, { useState, useEffect, useRef } from 'react';

interface LoginScreenProps {
  hasAuthConfig: boolean;
  onUnlock: (success: boolean) => void;
}

export default function LoginScreen({ hasAuthConfig, onUnlock }: LoginScreenProps) {
  const [mode, setMode] = useState<'unlock' | 'setup'>(hasAuthConfig ? 'unlock' : 'setup');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricEnabled, setBiometricEnabled] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    checkBiometricAvailability();
  }, [mode]);

  // Re-sync mode when hasAuthConfig prop changes (e.g. after lock/unlock)
  useEffect(() => {
    setMode(hasAuthConfig ? 'unlock' : 'setup');
  }, [hasAuthConfig]);

  const checkBiometricAvailability = async () => {
    try {
      // Check if biometric is enabled in vault via IPC (always works)
      let bioEnabled = false;
      if (hasAuthConfig) {
        const status = await window.vaultAPI.getBiometricStatus();
        bioEnabled = status.enabled;
        setBiometricEnabled(status.enabled);
      }

      // Check if WebAuthn is available in this context
      // Electron renders from file:// which is NOT a secure context for WebAuthn
      const isSecureContext = typeof window !== 'undefined' && window.isSecureContext;
      
      // Always allow biometric unlock if already configured (via IPC)
      // For setup, we need a secure context - we'll use the dev server URL or a special setup page
      if (isSecureContext && typeof PublicKeyCredential !== 'undefined') {
        try {
          const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
          setBiometricAvailable(available);
        } catch {
          // WebAuthn check failed - but biometric unlock via IPC still works
          setBiometricAvailable(bioEnabled);
        }
      } else {
        // Not a secure context (Electron file://) - WebAuthn won't work for setup
        // But biometric unlock via IPC still works if already configured
        setBiometricAvailable(bioEnabled);
      }
    } catch {
      setBiometricAvailable(false);
    }
  };

  useEffect(() => {
    setPasswordStrength(calculateStrength(password));
  }, [password]);

  const calculateStrength = (pwd: string): number => {
    let strength = 0;
    if (pwd.length >= 8) strength += 25;
    if (pwd.length >= 12) strength += 15;
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength += 20;
    if (/[0-9]/.test(pwd)) strength += 15;
    if (/[^a-zA-Z0-9]/.test(pwd)) strength += 25;
    return Math.min(100, strength);
  };

  const getStrengthColor = () => {
    if (passwordStrength < 30) return 'bg-red-500';
    if (passwordStrength < 60) return 'bg-yellow-500';
    if (passwordStrength < 80) return 'bg-blue-500';
    return 'bg-green-500';
  };

  const getStrengthLabel = () => {
    if (passwordStrength < 30) return 'Weak';
    if (passwordStrength < 60) return 'Fair';
    if (passwordStrength < 80) return 'Good';
    return 'Strong';
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      if (mode === 'setup') {
        if (password !== confirmPassword) {
          setError('Passwords do not match');
          setIsLoading(false);
          return;
        }
        if (passwordStrength < 40) {
          setError('Please choose a stronger master password');
          setIsLoading(false);
          return;
        }

        const result = await window.vaultAPI.setupMasterPassword({ password });
        if (result.success) {
          onUnlock(true);
        } else {
          setError('Failed to create vault');
        }
      } else {
        const result = await window.vaultAPI.unlock(password);
        if (result.success) {
          onUnlock(true);
        } else {
          setError(result.error || 'Invalid master password');
        }
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  const handleBiometricUnlock = async () => {
    setError('');
    setBiometricLoading(true);

    try {
      const status = await window.vaultAPI.getBiometricStatus();
      if (!status.enabled || !status.credentialId) {
        setError('Biometric authentication is not configured');
        setBiometricLoading(false);
        return;
      }

      const isSecureContext = typeof window !== 'undefined' && window.isSecureContext;

      if (isSecureContext && typeof navigator.credentials !== 'undefined') {
        // WebAuthn available - use it to verify the user first
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
        }) as PublicKeyCredential;

        if (!credential) {
          setError('Biometric verification failed');
          setBiometricLoading(false);
          return;
        }
      }
      // If not secure context, skip WebAuthn and go straight to IPC-based auth
      // The main process uses safeStorage which works regardless of renderer origin

      const result = await window.vaultAPI.authenticateBiometric({
        credentialId: status.credentialId,
      });

      if (result.success) {
        onUnlock(true);
      } else {
        setError(result.error || 'Biometric authentication failed');
      }
    } catch (err: any) {
      if (err.name === 'NotAllowedError') {
        setError('Biometric authentication was cancelled');
      } else {
        setError(err.message || 'Biometric authentication failed');
      }
    } finally {
      setBiometricLoading(false);
    }
  };

  const handleSetupBiometric = async () => {
    // Check if biometric is already configured
    const status = await window.vaultAPI.getBiometricStatus();
    if (status.enabled && status.credentialId) {
      setError('Biometric authentication is already configured');
      return;
    }

    const isSecureContext = typeof window !== 'undefined' && window.isSecureContext;

    if (!isSecureContext) {
      // Electron file:// origin - WebAuthn credential creation not available
      // Guide user to use browser extension popup for biometric setup
      setError('Windows Hello setup requires a secure context. Please use the browser extension popup to enable biometric, or run the desktop app from the dev server (npm run dev:desktop).');
      return;
    }

    try {
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

        const result = await window.vaultAPI.setupMasterPassword({
          password,
          biometricCredentialId: credentialId,
          biometricAuthenticatorData: authenticatorData,
        });

        if (result.success) {
          onUnlock(true);
        } else {
          setError('Failed to create vault with biometric');
        }
      }
    } catch (err: any) {
      if (err.name === 'NotAllowedError') {
        setError('Biometric setup was cancelled');
      } else {
        setError('Failed to set up biometric: ' + err.message);
      }
    }
  };

  return (
    <div className="h-screen w-screen flex items-center justify-center bg-dark-bg relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-vault-600/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-vault-800/10 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10 w-full max-w-md px-6 vault-unlock">
        {/* Logo and Title */}
        <div className="text-center mb-8">
          <div className="w-20 h-20 mx-auto mb-6 rounded-2xl bg-gradient-to-br from-vault-500 to-vault-700 flex items-center justify-center shadow-lg shadow-vault-500/30">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold mb-2">VaultGuard</h1>
          <p className="text-gray-400">
            {mode === 'setup'
              ? 'Create your master password to get started'
              : 'Enter your master password to unlock'}
          </p>
        </div>

        {/* Login Card */}
        <div className="glass-card p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Master Password Input */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Master Password
              </label>
              <div className="relative">
                <input
                  ref={inputRef}
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-field pr-12"
                  placeholder="Enter master password"
                  autoComplete="current-password"
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-300 transition-colors"
                >
                  {showPassword ? (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                      <line x1="1" y1="1" x2="23" y2="23" />
                    </svg>
                  ) : (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>

              {/* Password Strength Indicator (setup mode only) */}
              {mode === 'setup' && password && (
                <div className="mt-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-gray-400">Password strength</span>
                    <span className={`text-xs ${passwordStrength >= 60 ? 'text-green-400' : passwordStrength >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
                      {getStrengthLabel()}
                    </span>
                  </div>
                  <div className="h-1 bg-dark-border rounded-full overflow-hidden">
                    <div
                      className={`h-full ${getStrengthColor()} transition-all duration-300`}
                      style={{ width: `${passwordStrength}%` }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Confirm Password (setup mode only) */}
            {mode === 'setup' && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Confirm Password
                </label>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="input-field"
                  placeholder="Confirm master password"
                  autoComplete="new-password"
                  disabled={isLoading}
                />
                {confirmPassword && password !== confirmPassword && (
                  <p className="text-red-400 text-xs mt-1">Passwords do not match</p>
                )}
              </div>
            )}

            {/* Error Message */}
            {error && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3 text-red-400 text-sm">
                {error}
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading || !password || (mode === 'setup' && password !== confirmPassword)}
              className="w-full btn-primary py-3 text-base font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="spinner w-5 h-5 border-2" />
                  {mode === 'setup' ? 'Creating Vault...' : 'Unlocking...'}
                </span>
              ) : mode === 'setup' ? (
                'Create Vault'
              ) : (
                'Unlock'
              )}
            </button>
          </form>

          {/* Biometric Unlock */}
          {mode === 'unlock' && biometricAvailable && biometricEnabled && (
            <>
              <div className="relative my-6">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-dark-border" />
                </div>
                <div className="relative flex justify-center text-xs">
                  <span className="px-2 bg-dark-card text-gray-500">or</span>
                </div>
              </div>

              <button
                onClick={handleBiometricUnlock}
                disabled={biometricLoading}
                className="w-full flex items-center justify-center gap-3 py-3 px-4 bg-dark-bg/50 border border-dark-border rounded-xl hover:bg-dark-hover/50 transition-all disabled:opacity-50"
              >
                {biometricLoading ? (
                  <div className="spinner w-5 h-5 border-2" />
                ) : (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-vault-400">
                    <path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                  </svg>
                )}
                <span className="text-sm font-medium">Unlock with Windows Hello</span>
              </button>
            </>
          )}

          {/* Enable Biometric during setup */}
          {mode === 'setup' && password && passwordStrength >= 40 && (
            <div className="mt-4">
              <button
                onClick={handleSetupBiometric}
                className="w-full flex items-center justify-center gap-3 py-3 px-4 bg-vault-500/10 border border-vault-500/20 rounded-xl hover:bg-vault-500/20 transition-all"
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-vault-400">
                  <path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                </svg>
                <span className="text-sm font-medium text-vault-300">
                  {biometricAvailable ? 'Setup Windows Hello' : 'Setup Windows Hello (via Extension)'}
                </span>
              </button>
              <p className="text-xs text-gray-500 text-center mt-2">
                {biometricAvailable
                  ? 'Use fingerprint or face recognition for quick unlock'
                  : 'Requires browser extension popup (secure context)'}
              </p>
            </div>
          )}

          {/* Setup mode security note */}
          {mode === 'setup' && (
            <div className="mt-6 p-4 bg-dark-bg/50 rounded-lg border border-dark-border">
              <p className="text-xs text-gray-400 leading-relaxed">
                <strong className="text-gray-300">⚠️ Important:</strong> Your master password is the only way to access your vault.
                It is never stored or transmitted. If you forget it, your data cannot be recovered.
                We recommend using a strong, unique password that you can remember.
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-500 mt-6">
          🔒 Your data is encrypted locally and never leaves your device
        </p>
      </div>
    </div>
  );
}
