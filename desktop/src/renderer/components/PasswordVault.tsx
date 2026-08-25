import React, { useState, useEffect } from 'react';
import { PasswordEntry } from '@vaultguard/shared';

export default function PasswordVault() {
  const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingEntry, setEditingEntry] = useState<PasswordEntry | null>(null);
  const [showPasswordId, setShowPasswordId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    loadPasswords();
  }, []);

  const loadPasswords = async () => {
    try {
      const result = await window.vaultAPI.getPasswords();
      if (Array.isArray(result)) setPasswords(result);
    } catch (err) {
      console.error('Failed to load passwords:', err);
    }
  };

  const handleSearch = async (query: string) => {
    setSearchQuery(query);
    if (query.trim()) {
      const results = await window.vaultAPI.searchPasswords(query);
      if (Array.isArray(results)) setPasswords(results);
    } else {
      loadPasswords();
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this password?')) {
      await window.vaultAPI.deletePassword(id);
      loadPasswords();
    }
  };

  const handleCopy = async (text: string, id: string, type: string) => {
    await window.vaultAPI.copyToClipboard(text);
    setCopiedId(`${id}-${type}`);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const filteredPasswords = passwords.filter((p) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      p.title.toLowerCase().includes(q) ||
      p.username.toLowerCase().includes(q) ||
      (p.url && p.url.toLowerCase().includes(q))
    );
  });

  const getFavicon = (url?: string) => {
    if (!url) return null;
    try {
      const urlObj = new URL(url);
      return `https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=32`;
    } catch {
      return null;
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Password Vault</h1>
          <p className="text-gray-400 text-sm mt-1">{passwords.length} passwords stored securely</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="btn-primary flex items-center gap-2"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          Add Password
        </button>
      </div>

      {/* Search */}
      <div className="relative">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => handleSearch(e.target.value)}
          className="input-field pl-12"
          placeholder="Search passwords..."
        />
      </div>

      {/* Password List */}
      <div className="space-y-2">
        {filteredPasswords.length === 0 ? (
          <div className="glass-card p-12 text-center">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mx-auto mb-4 text-gray-500">
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
            </svg>
            <p className="text-gray-400">No passwords found</p>
            <p className="text-sm text-gray-500 mt-1">Click "Add Password" to get started</p>
          </div>
        ) : (
          filteredPasswords.map((entry) => (
            <div
              key={entry.id}
              className="glass-card p-4 glass-card-hover transition-all group"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-xl bg-gray-700/50 flex items-center justify-center overflow-hidden">
                    {getFavicon(entry.url) ? (
                      <img src={getFavicon(entry.url)!} alt="" className="w-6 h-6" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
                    ) : (
                      <span className="text-sm text-gray-400 font-medium">{entry.title[0].toUpperCase()}</span>
                    )}
                  </div>
                  <div>
                    <h3 className="font-medium">{entry.title}</h3>
                    <p className="text-sm text-gray-400">{entry.username}</p>
                    {entry.url && (
                      <p className="text-xs text-gray-500 mt-0.5 truncate max-w-xs">{entry.url}</p>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-1">
                  {/* Copy Username */}
                  <button
                    onClick={() => handleCopy(entry.username, entry.id, 'user')}
                    className={`p-2 rounded-lg transition-all ${
                      copiedId === `${entry.id}-user`
                        ? 'bg-green-500/20 text-green-400'
                        : 'hover:bg-vault-500/20 text-gray-400 hover:text-vault-400'
                    }`}
                    title="Copy username"
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      {copiedId === `${entry.id}-user` ? (
                        <polyline points="20 6 9 17 4 12" />
                      ) : (
                        <>
                          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                          <circle cx="12" cy="7" r="4" />
                        </>
                      )}
                    </svg>
                  </button>

                  {/* Copy Password */}
                  <button
                    onClick={() => handleCopy(entry.password, entry.id, 'pass')}
                    className={`p-2 rounded-lg transition-all ${
                      copiedId === `${entry.id}-pass`
                        ? 'bg-green-500/20 text-green-400'
                        : 'hover:bg-vault-500/20 text-gray-400 hover:text-vault-400'
                    }`}
                    title="Copy password"
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      {copiedId === `${entry.id}-pass` ? (
                        <polyline points="20 6 9 17 4 12" />
                      ) : (
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                      )}
                    </svg>
                  </button>

                  {/* Toggle Show Password */}
                  <button
                    onClick={() => setShowPasswordId(showPasswordId === entry.id ? null : entry.id)}
                    className="p-2 rounded-lg hover:bg-dark-hover text-gray-400 hover:text-gray-300 transition-all"
                    title="Show password"
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      {showPasswordId === entry.id ? (
                        <>
                          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                          <line x1="1" y1="1" x2="23" y2="23" />
                        </>
                      ) : (
                        <>
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                          <circle cx="12" cy="12" r="3" />
                        </>
                      )}
                    </svg>
                  </button>

                  {/* Edit */}
                  <button
                    onClick={() => { setEditingEntry(entry); setShowAddModal(true); }}
                    className="p-2 rounded-lg hover:bg-dark-hover text-gray-400 hover:text-gray-300 transition-all"
                    title="Edit"
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                      <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                    </svg>
                  </button>

                  {/* Delete */}
                  <button
                    onClick={() => handleDelete(entry.id)}
                    className="p-2 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-all"
                    title="Delete"
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="3 6 5 6 21 6" />
                      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                    </svg>
                  </button>
                </div>
              </div>

              {/* Show Password */}
              {showPasswordId === entry.id && (
                <div className="mt-3 p-3 bg-dark-bg/50 rounded-lg">
                  <div className="flex items-center justify-between">
                    <code className="text-sm font-mono text-vault-300">{entry.password}</code>
                    <button
                      onClick={() => handleCopy(entry.password, entry.id, 'pass')}
                      className="text-xs text-gray-400 hover:text-vault-400 transition-colors"
                    >
                      Copy
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Add/Edit Modal */}
      {showAddModal && (
        <PasswordModal
          entry={editingEntry}
          onClose={() => { setShowAddModal(false); setEditingEntry(null); }}
          onSave={async (data) => {
            if (editingEntry) {
              await window.vaultAPI.updatePassword(editingEntry.id, data);
            } else {
              await window.vaultAPI.addPassword(data);
            }
            setShowAddModal(false);
            setEditingEntry(null);
            loadPasswords();
          }}
        />
      )}
    </div>
  );
}

function PasswordModal({ entry, onClose, onSave }: {
  entry: PasswordEntry | null;
  onClose: () => void;
  onSave: (data: any) => Promise<void>;
}) {
  const [title, setTitle] = useState(entry?.title || '');
  const [username, setUsername] = useState(entry?.username || '');
  const [password, setPassword] = useState(entry?.password || '');
  const [url, setUrl] = useState(entry?.url || '');
  const [notes, setNotes] = useState(entry?.notes || '');
  const [showPassword, setShowPassword] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  const generatePassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let result = '';
    for (let i = 0; i < 20; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setPassword(result);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    await onSave({ title, username, password, url, notes, category: 'general' });
    setIsSaving(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center modal-backdrop" onClick={onClose}>
      <div className="glass-card w-full max-w-lg p-6 animate-slide-in" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold">{entry ? 'Edit Password' : 'Add New Password'}</h2>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-dark-hover text-gray-400 hover:text-white transition-all">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-gray-300 mb-1">Title</label>
            <input type="text" value={title} onChange={(e) => setTitle(e.target.value)} className="input-field" placeholder="e.g., Google Account" required />
          </div>

          <div>
            <label className="block text-sm text-gray-300 mb-1">Username / Email</label>
            <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="input-field" placeholder="e.g., user@example.com" required />
          </div>

          <div>
            <label className="block text-sm text-gray-300 mb-1">Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-field pr-24"
                placeholder="Enter password"
                required
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                <button type="button" onClick={() => setShowPassword(!showPassword)} className="p-1.5 rounded text-gray-400 hover:text-gray-300">
                  {showPassword ? (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                      <line x1="1" y1="1" x2="23" y2="23" />
                    </svg>
                  ) : (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
                <button type="button" onClick={generatePassword} className="px-2 py-1 rounded text-xs bg-vault-500/20 text-vault-400 hover:bg-vault-500/30 transition-colors">
                  Generate
                </button>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-300 mb-1">Website URL</label>
            <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} className="input-field" placeholder="https://example.com" />
          </div>

          <div>
            <label className="block text-sm text-gray-300 mb-1">Notes</label>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} className="input-field h-20 resize-none" placeholder="Optional notes..." />
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={isSaving} className="btn-primary">
              {isSaving ? 'Saving...' : entry ? 'Update' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
