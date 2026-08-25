import React, { useState, useCallback, useEffect } from 'react';

interface PasswordGeneratorProps {
  onUsePassword?: (password: string) => void;
}

interface GeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

const CHARS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  ambiguous: 'Il1O0',
};

export default function PasswordGenerator({ onUsePassword }: PasswordGeneratorProps) {
  const [password, setPassword] = useState('');
  const [options, setOptions] = useState<GeneratorOptions>({
    length: 20,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeAmbiguous: false,
  });
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState<Array<{ password: string; id: string }>>([]);

  const generatePassword = useCallback(() => {
    let charset = '';
    
    if (options.uppercase) charset += CHARS.uppercase;
    if (options.lowercase) charset += CHARS.lowercase;
    if (options.numbers) charset += CHARS.numbers;
    if (options.symbols) charset += CHARS.symbols;

    if (options.excludeAmbiguous) {
      charset = charset.split('').filter(c => !CHARS.ambiguous.includes(c)).join('');
    }

    if (!charset) {
      // Ensure at least one character type is available
      charset = CHARS.lowercase;
      setPassword('Please select at least one character type');
      return;
    }

    const array = new Uint32Array(options.length);
    crypto.getRandomValues(array);
    
    let result = '';
    for (let i = 0; i < options.length; i++) {
      result += charset[array[i] % charset.length];
    }

    setPassword(result);
    setHistory(prev => [{ password: result, id: Date.now().toString(36) + Math.random().toString(36).substr(2) }, ...prev].slice(0, 10));
  }, [options]);

  useEffect(() => {
    generatePassword();
  }, [generatePassword]);

  const calculateStrength = (pwd: string): { score: number; label: string; color: string } => {
    let score = 0;
    if (pwd.length >= 8) score += 1;
    if (pwd.length >= 12) score += 1;
    if (pwd.length >= 16) score += 1;
    if (pwd.length >= 20) score += 1;
    if (/[a-z]/.test(pwd)) score += 1;
    if (/[A-Z]/.test(pwd)) score += 1;
    if (/[0-9]/.test(pwd)) score += 1;
    if (/[^a-zA-Z0-9]/.test(pwd)) score += 1;

    if (score <= 2) return { score: 25, label: 'Weak', color: 'bg-red-500' };
    if (score <= 4) return { score: 50, label: 'Fair', color: 'bg-yellow-500' };
    if (score <= 6) return { score: 75, label: 'Good', color: 'bg-blue-500' };
    return { score: 100, label: 'Strong', color: 'bg-green-500' };
  };

  const strength = calculateStrength(password);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = password;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Password Generator</h1>
        <p className="text-gray-400 text-sm mt-1">Generate strong, secure passwords</p>
      </div>

      {/* Generated Password */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-4">
          <label className="text-sm text-gray-400">Generated Password</label>
          <div className="flex gap-2">
            <button
              onClick={generatePassword}
              className="p-2 rounded-lg hover:bg-dark-hover text-gray-400 hover:text-vault-400 transition-all"
              title="Regenerate"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="23 4 23 10 17 10"/>
                <polyline points="1 20 1 14 7 14"/>
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
              </svg>
            </button>
            <button
              onClick={copyToClipboard}
              className={`p-2 rounded-lg transition-all ${
                copied 
                  ? 'bg-green-500/20 text-green-400' 
                  : 'hover:bg-dark-hover text-gray-400 hover:text-vault-400'
              }`}
              title="Copy to clipboard"
            >
              {copied ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                </svg>
              )}
            </button>
          </div>
        </div>

        <div className="bg-dark-bg/50 rounded-xl p-4 font-mono text-lg break-all">
          {password}
        </div>

        {/* Strength Indicator */}
        <div className="mt-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-gray-400">Strength</span>
            <span className={`text-xs font-medium ${
              strength.score >= 75 ? 'text-green-400' : 
              strength.score >= 50 ? 'text-yellow-400' : 'text-red-400'
            }`}>
              {strength.label}
            </span>
          </div>
          <div className="h-2 bg-dark-border rounded-full overflow-hidden">
            <div
              className={`h-full ${strength.color} transition-all duration-300`}
              style={{ width: `${strength.score}%` }}
            />
          </div>
        </div>

        {/* Use Password Button */}
        {onUsePassword && (
          <button
            onClick={() => onUsePassword(password)}
            className="w-full mt-4 btn-primary"
          >
            Use This Password
          </button>
        )}
      </div>

      {/* Options */}
      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4">Options</h2>

        {/* Length Slider */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <label className="text-sm text-gray-300">Length</label>
            <span className="text-sm font-mono text-vault-400">{options.length}</span>
          </div>            <input
              type="range"
              min="8"
              max="64"
              value={options.length}
              onChange={(e) => {
                setOptions({ ...options, length: parseInt(e.target.value) });
              }}
            className="w-full h-2 bg-dark-border rounded-lg appearance-none cursor-pointer accent-vault-500"
          />
          <div className="flex justify-between text-xs text-gray-500 mt-1">
            <span>8</span>
            <span>64</span>
          </div>
        </div>

        {/* Character Type Toggles */}
        <div className="space-y-3">
          <ToggleOption
            label="Uppercase (A-Z)"
            checked={options.uppercase}
            onChange={(v) => setOptions({ ...options, uppercase: v })}
          />
          <ToggleOption
            label="Lowercase (a-z)"
            checked={options.lowercase}
            onChange={(v) => setOptions({ ...options, lowercase: v })}
          />
          <ToggleOption
            label="Numbers (0-9)"
            checked={options.numbers}
            onChange={(v) => setOptions({ ...options, numbers: v })}
          />
          <ToggleOption
            label="Symbols (!@#$%)"
            checked={options.symbols}
            onChange={(v) => setOptions({ ...options, symbols: v })}
          />
          <ToggleOption
            label="Exclude ambiguous characters (I, l, 1, O, 0)"
            checked={options.excludeAmbiguous}
            onChange={(v) => setOptions({ ...options, excludeAmbiguous: v })}
          />
        </div>

        <button onClick={generatePassword} className="w-full mt-6 btn-primary">
          Generate New Password
        </button>
      </div>

      {/* History */}
      {history.length > 0 && (
        <div className="glass-card p-6">
          <h2 className="text-lg font-semibold mb-4">Recent Passwords</h2>
          <div className="space-y-2">
            {history.map((item) => (
              <div key={item.id} className="flex items-center justify-between p-2 bg-dark-bg/30 rounded-lg">
                <code className="text-xs text-gray-400 truncate flex-1 mr-2">{item.password}</code>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(item.password);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1500);
                  }}
                  className="p-1.5 rounded hover:bg-dark-hover text-gray-400 hover:text-vault-400 transition-all"
                  title="Copy"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                  </svg>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ToggleOption({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center justify-between py-2 cursor-pointer">
      <span className="text-sm text-gray-300">{label}</span>
      <button
        type="button"
        onClick={() => onChange(!checked)}
        className={`relative w-11 h-6 rounded-full transition-colors ${checked ? 'bg-vault-500' : 'bg-dark-border'}`}
      >
        <div
          className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${checked ? 'left-6' : 'left-1'}`}
        />
      </button>
    </label>
  );
}
