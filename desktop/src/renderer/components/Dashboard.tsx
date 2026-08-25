import React, { useState, useEffect } from 'react';
import { PasswordEntry, TwoFactorEntry } from '@vaultguard/shared';

export default function Dashboard() {
  const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
  const [totpEntries, setTotpEntries] = useState<TwoFactorEntry[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [currentTime, setCurrentTime] = useState(Date.now());

  useEffect(() => {
    loadData();
    const timer = setInterval(() => setCurrentTime(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const loadData = async () => {
    try {
      const [pwds, totps] = await Promise.all([
        window.vaultAPI.getPasswords(),
        window.vaultAPI.getTotpEntries(),
      ]);
      if (Array.isArray(pwds)) setPasswords(pwds);
      if (Array.isArray(totps)) setTotpEntries(totps);
    } catch (err) {
      console.error('Failed to load data:', err);
    }
  };

  const generateCode = async (secret: string): Promise<string> => {
    try {
      return await window.vaultAPI.generateTotp(secret);
    } catch {
      return '------';
    }
  };

  const copyToClipboard = async (text: string, label: string) => {
    await window.vaultAPI.copyToClipboard(text);
  };

  // Stats
  const categories = passwords.reduce((acc, p) => {
    const cat = p.category || 'Uncategorized';
    acc[cat] = (acc[cat] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Get time remaining for TOTP
  const getTimeRemaining = (period: number = 30) => {
    const epoch = Math.floor(currentTime / 1000);
    return period - (epoch % period);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-gray-400 text-sm mt-1">Your security overview</p>
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-400">Last updated</p>
          <p className="text-sm font-mono">{new Date().toLocaleTimeString()}</p>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          title="Passwords"
          value={passwords.length}
          icon={
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
            </svg>
          }
          color="vault"
        />
        <StatCard
          title="2FA Codes"
          value={totpEntries.length}
          icon={
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          }
          color="green"
        />
        <StatCard
          title="Categories"
          value={Object.keys(categories).length}
          icon={
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
            </svg>
          }
          color="blue"
        />
        <StatCard
          title="Security Score"
          value={calculateSecurityScore(passwords, totpEntries)}
          suffix="%"
          icon={
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          }
          color="yellow"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-2 gap-6">
        {/* Active 2FA Codes */}
        <div className="glass-card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Active 2FA Codes</h2>
            <span className="text-xs text-gray-400">Auto-refreshing</span>
          </div>

          <div className="space-y-3">
            {totpEntries.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-8">No 2FA codes yet</p>
            ) : (
              totpEntries.slice(0, 5).map((entry) => (
                <TotpCodeCard
                  key={entry.id}
                  entry={entry}
                  currentTime={currentTime}
                  onCopy={copyToClipboard}
                />
              ))
            )}
          </div>
        </div>

        {/* Recent Passwords */}
        <div className="glass-card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Recent Passwords</h2>
            <span className="text-xs text-gray-400">{passwords.length} total</span>
          </div>

          <div className="space-y-3">
            {passwords.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-8">No passwords saved yet</p>
            ) : (
              passwords.slice(0, 5).map((entry) => (
                <PasswordCard
                  key={entry.id}
                  entry={entry}
                  onCopy={copyToClipboard}
                />
              ))
            )}
          </div>
        </div>
      </div>

      {/* Browser Extension Status */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500/20 to-blue-600/20 flex items-center justify-center">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-blue-400">
                <circle cx="12" cy="12" r="10" />
                <circle cx="12" cy="12" r="4" />
                <line x1="21.17" y1="8" x2="12" y2="8" />
                <line x1="3.95" y1="6.06" x2="8.54" y2="14" />
                <line x1="10.88" y1="21.94" x2="15.46" y2="14" />
              </svg>
            </div>
            <div>
              <h3 className="font-semibold">Browser Extension</h3>
              <p className="text-sm text-gray-400">Auto-fill and 2FA detection on web pages</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-sm text-green-400">Connected</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// --- Sub-components ---

function StatCard({ title, value, icon, color, suffix = '' }: {
  title: string;
  value: number;
  icon: React.ReactNode;
  color: string;
  suffix?: string;
}) {
  const colorClasses: Record<string, string> = {
    vault: 'from-vault-500/20 to-vault-600/20 text-vault-400',
    green: 'from-green-500/20 to-green-600/20 text-green-400',
    blue: 'from-blue-500/20 to-blue-600/20 text-blue-400',
    yellow: 'from-yellow-500/20 to-yellow-600/20 text-yellow-400',
  };

  return (
    <div className="glass-card p-5 glass-card-hover transition-all">
      <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${colorClasses[color]} flex items-center justify-center mb-3`}>
        {icon}
      </div>
      <p className="text-2xl font-bold">
        {value}{suffix}
      </p>
      <p className="text-sm text-gray-400 mt-1">{title}</p>
    </div>
  );
}

function TotpCodeCard({ entry, currentTime, onCopy }: {
  entry: TwoFactorEntry;
  currentTime: number;
  onCopy: (text: string, label: string) => void;
}) {
  const [code, setCode] = useState('------');
  const period = entry.period || 30;
  const timeRemaining = period - (Math.floor(currentTime / 1000) % period);
  const progress = (timeRemaining / period) * 100;

  useEffect(() => {
    window.vaultAPI.generateTotp(entry.secret, {
      algorithm: entry.algorithm,
      digits: entry.digits,
      period: entry.period,
    }).then(setCode);
  }, [entry, currentTime]);

  const formatCode = (code: string) => {
    if (code.length === 6) {
      return `${code.slice(0, 3)} ${code.slice(3)}`;
    }
    return code;
  };

  return (
    <div className="flex items-center justify-between p-3 bg-dark-bg/50 rounded-lg hover:bg-dark-hover/50 transition-colors group">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-vault-500/20 flex items-center justify-center text-vault-400 text-xs font-bold">
          {(entry.issuer || entry.title)[0].toUpperCase()}
        </div>
        <div>
          <p className="text-sm font-medium">{entry.title}</p>
          <p className="text-xs text-gray-500">{entry.issuer || 'Personal'}</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="text-right">
          <p className="totp-code text-lg font-bold text-vault-300">{formatCode(code)}</p>
          <div className="flex items-center gap-2 mt-1">
            <div className="w-16 h-1 bg-dark-border rounded-full overflow-hidden">
              <div
                className={`h-full totp-progress rounded-full ${
                  timeRemaining <= 5 ? 'bg-red-500' : timeRemaining <= 10 ? 'bg-yellow-500' : 'bg-green-500'
                }`}
                style={{ width: `${progress}%` }}
              />
            </div>
            <span className="text-xs text-gray-500 font-mono">{timeRemaining}s</span>
          </div>
        </div>

        <button
          onClick={() => onCopy(code, entry.title)}
          className="p-2 rounded-lg hover:bg-vault-500/20 text-gray-400 hover:text-vault-400 transition-all opacity-0 group-hover:opacity-100"
          title="Copy code"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
        </button>
      </div>
    </div>
  );
}

function PasswordCard({ entry, onCopy }: {
  entry: PasswordEntry;
  onCopy: (text: string, label: string) => void;
}) {
  const getFavicon = (url?: string) => {
    if (!url) return null;
    try {
      const urlObj = new URL(url);
      return `https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=32`;
    } catch {
      return null;
    }
  };

  const favicon = getFavicon(entry.url);

  return (
    <div className="flex items-center justify-between p-3 bg-dark-bg/50 rounded-lg hover:bg-dark-hover/50 transition-colors group">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-gray-700/50 flex items-center justify-center overflow-hidden">
          {favicon ? (
            <img src={favicon} alt="" className="w-5 h-5" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
          ) : (
            <span className="text-xs text-gray-400">{entry.title[0].toUpperCase()}</span>
          )}
        </div>
        <div>
          <p className="text-sm font-medium">{entry.title}</p>
          <p className="text-xs text-gray-500">{entry.username}</p>
        </div>
      </div>

      <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <button
          onClick={() => onCopy(entry.username, `${entry.title} username`)}
          className="p-2 rounded-lg hover:bg-vault-500/20 text-gray-400 hover:text-vault-400 transition-all"
          title="Copy username"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
            <circle cx="12" cy="7" r="4" />
          </svg>
        </button>
        <button
          onClick={() => onCopy(entry.password, `${entry.title} password`)}
          className="p-2 rounded-lg hover:bg-vault-500/20 text-gray-400 hover:text-vault-400 transition-all"
          title="Copy password"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
        </button>
      </div>
    </div>
  );
}

function calculateSecurityScore(passwords: PasswordEntry[], totpEntries: TwoFactorEntry[]): number {
  if (passwords.length === 0 && totpEntries.length === 0) return 0;

  let score = 0;
  let total = 0;

  // Check password quality
  passwords.forEach((p) => {
    total += 10;
    if (p.password.length >= 12) score += 5;
    if (p.password.length >= 16) score += 2;
    if (/[A-Z]/.test(p.password) && /[a-z]/.test(p.password)) score += 1;
    if (/[0-9]/.test(p.password)) score += 1;
    if (/[^a-zA-Z0-9]/.test(p.password)) score += 1;
  });

  // Check 2FA adoption
  const urls = new Set(passwords.filter((p) => p.url).map((p) => {
    try { return new URL(p.url!).hostname; } catch { return ''; }
  }).filter(Boolean));

  const totpUrls = new Set(totpEntries.filter((t) => t.uri).map((t) => {
    try { return new URL(t.uri!.replace('otpauth://', 'https://')).hostname; } catch { return ''; }
  }).filter(Boolean));

  urls.forEach((url) => {
    total += 5;
    if (totpUrls.has(url)) score += 5;
  });

  return total > 0 ? Math.min(100, Math.round((score / total) * 100)) : 0;
}
