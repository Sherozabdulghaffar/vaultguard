import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { OtpCodeResult, TwoFactorEntry } from '@vaultguard/shared';

// Must match the SVG below and the --ring-circumference custom property.
const RING_RADIUS = 15;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

type Draft = {
  title: string;
  issuer: string;
  account: string;
  secret: string;
  type: 'TOTP' | 'HOTP';
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: number;
  period: number;
  counter: number;
  encoding: 'base32' | 'hex' | 'ascii';
  steam: boolean;
  notes: string;
};

/** Group a code the way authenticator apps do: 6/7 → 3 + rest, 8 → 4 + 4. */
function formatCode(code: string, digits: number): string {
  if (!code) return '•'.repeat(Math.max(6, digits));
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  if (code.length === 6 || code.length === 7) return `${code.slice(0, 3)} ${code.slice(3)}`;
  return code; // 5-character Steam codes are not grouped
}

/** Pinned first, then manual order, then creation time. */
function sortEntries(list: TwoFactorEntry[]): TwoFactorEntry[] {
  return [...list].sort((a, b) => {
    if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1;
    const orderA = a.order ?? Number.MAX_SAFE_INTEGER;
    const orderB = b.order ?? Number.MAX_SAFE_INTEGER;
    if (orderA !== orderB) return orderA - orderB;
    return a.createdAt - b.createdAt;
  });
}

function displayName(entry: TwoFactorEntry): string {
  return entry.issuer || entry.title || entry.account || 'Unnamed';
}

/** First letter of the issuer, guarded against empty strings. */
function avatarLetter(entry: TwoFactorEntry): string {
  const source = displayName(entry).trim();
  return source ? source[0].toUpperCase() : '?';
}

/** Stable per-issuer hue so each account keeps the same colour between runs. */
function avatarHue(entry: TwoFactorEntry): number {
  const source = displayName(entry).toLowerCase();
  let hash = 0;
  for (let i = 0; i < source.length; i++) hash = (hash * 31 + source.charCodeAt(i)) % 360;
  return hash;
}

function emptyDraft(): Draft {
  return {
    title: '', issuer: '', account: '', secret: '', type: 'TOTP', algorithm: 'SHA1',
    digits: 6, period: 30, counter: 0, encoding: 'base32', steam: false, notes: '',
  };
}

function draftFrom(entry: TwoFactorEntry): Draft {
  return {
    title: entry.title || '',
    issuer: entry.issuer || '',
    account: entry.account || '',
    secret: entry.secret || '',
    type: entry.type === 'HOTP' ? 'HOTP' : 'TOTP',
    algorithm: entry.algorithm || 'SHA1',
    digits: entry.digits || 6,
    period: entry.period || 30,
    counter: entry.counter ?? 0,
    encoding: entry.encoding || 'base32',
    steam: !!entry.steam,
    notes: entry.notes || '',
  };
}

export default function TwoFactorVault() {
  const [entries, setEntries] = useState<TwoFactorEntry[]>([]);
  const [codes, setCodes] = useState<Record<string, OtpCodeResult>>({});
  const [search, setSearch] = useState('');
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: 'error' | 'success'; text: string } | null>(null);
  const [loading, setLoading] = useState(true);

  const [editor, setEditor] = useState<{ entry: TwoFactorEntry | null } | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [qr, setQr] = useState<{ title: string; uri: string; dataUrl: string } | null>(null);

  const [dragId, setDragId] = useState<string | null>(null);
  const [dropId, setDropId] = useState<string | null>(null);

  const copyTimer = useRef<number | null>(null);
  const bannerTimer = useRef<number | null>(null);

  const notify = useCallback((kind: 'error' | 'success', text: string) => {
    setBanner({ kind, text });
    if (bannerTimer.current) window.clearTimeout(bannerTimer.current);
    bannerTimer.current = window.setTimeout(() => setBanner(null), 4000);
  }, []);

  /**
   * One IPC round-trip for every code on screen. The old implementation asked
   * the main process for one code per card per second, so the list flickered
   * as ~12 promises resolved out of order every second.
   */
  const refreshCodes = useCallback(async () => {
    try {
      const results = await window.vaultAPI.generateTotpBatch({ withNext: true });
      setCodes(Object.fromEntries(results.map((r) => [r.id, r])));
    } catch (err: any) {
      notify('error', err?.message || 'Could not generate codes');
    }
  }, [notify]);

  const loadEntries = useCallback(async () => {
    try {
      const list = await window.vaultAPI.getTotpEntries();
      setEntries(sortEntries(Array.isArray(list) ? list : []));
    } catch (err: any) {
      notify('error', err?.message || 'Could not load 2FA accounts');
    } finally {
      setLoading(false);
    }
  }, [notify]);

  useEffect(() => {
    loadEntries().then(refreshCodes);

    // Polled twice a second, but React bails out when the value is unchanged,
    // so the grid still re-renders only once per second.
    const tick = window.setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 500);

    // The extension can add entries or advance an HOTP counter behind our back.
    const unsubChanged = window.vaultAPI?.onVaultChanged?.(() => {
      loadEntries().then(refreshCodes);
    });

    return () => {
      window.clearInterval(tick);
      unsubChanged?.();
      if (copyTimer.current) window.clearTimeout(copyTimer.current);
      if (bannerTimer.current) window.clearTimeout(bannerTimer.current);
    };
  }, [loadEntries, refreshCodes]);

  /**
   * Refresh exactly when the soonest code expires instead of polling every
   * second. Entries with mixed periods (15/30/60s) all stay correct because
   * the nearest boundary always wins.
   */
  useEffect(() => {
    const live = Object.values(codes).filter((c) => !c.error && c.expiresAt > 0);
    if (!live.length) return;
    const soonest = Math.min(...live.map((c) => c.expiresAt));
    // A small grace period keeps us on the far side of the boundary even if
    // the timer fires a few milliseconds early.
    const delay = Math.max(250, soonest - Date.now() + 120);
    const timer = window.setTimeout(refreshCodes, delay);
    return () => window.clearTimeout(timer);
  }, [codes, refreshCodes]);

  const handleCopy = useCallback(async (entry: TwoFactorEntry, code: string) => {
    if (!code) return;
    await window.vaultAPI.copyToClipboard(code);
    setCopiedId(entry.id);
    if (copyTimer.current) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopiedId(null), 1800);
  }, []);

  const handleDelete = useCallback(async (entry: TwoFactorEntry) => {
    const label = [entry.issuer, entry.account].filter(Boolean).join(' — ') || entry.title;
    if (!confirm(`Remove "${label}"?\n\nYou will lose access to this account unless you have another copy of its secret or its recovery codes.`)) return;
    try {
      await window.vaultAPI.deleteTotpEntry(entry.id);
      await loadEntries();
      await refreshCodes();
      notify('success', 'Account removed');
    } catch (err: any) {
      notify('error', err?.message || 'Could not remove the account');
    }
  }, [loadEntries, refreshCodes, notify]);

  const handleTogglePin = useCallback(async (entry: TwoFactorEntry) => {
    try {
      await window.vaultAPI.updateTotpEntry(entry.id, { pinned: !entry.pinned });
      await loadEntries();
    } catch (err: any) {
      notify('error', err?.message || 'Could not pin the account');
    }
  }, [loadEntries, notify]);

  const handleIncrementHotp = useCallback(async (entry: TwoFactorEntry) => {
    try {
      const result = await window.vaultAPI.incrementHotp(entry.id);
      setCodes((prev) => ({ ...prev, [result.id]: result }));
      setEntries((prev) => prev.map((e) => (e.id === entry.id ? { ...e, counter: result.counter } : e)));
    } catch (err: any) {
      notify('error', err?.message || 'Could not advance the counter');
    }
  }, [notify]);

  const handleShowQr = useCallback(async (entry: TwoFactorEntry) => {
    try {
      const result = await window.vaultAPI.getTotpQr(entry.id);
      setQr({ title: displayName(entry), ...result });
    } catch (err: any) {
      notify('error', err?.message || 'Could not build the QR code');
    }
  }, [notify]);

  const handleSave = useCallback(async (draft: Draft, existing: TwoFactorEntry | null) => {
    const payload = {
      title: draft.title.trim() || draft.issuer.trim() || draft.account.trim(),
      issuer: draft.issuer.trim() || undefined,
      account: draft.account.trim() || undefined,
      secret: draft.secret.replace(/\s+/g, ''),
      type: draft.type,
      algorithm: draft.algorithm,
      digits: draft.steam ? 5 : draft.digits,
      period: draft.period,
      counter: draft.type === 'HOTP' ? draft.counter : undefined,
      encoding: draft.encoding,
      steam: draft.steam || undefined,
      notes: draft.notes.trim() || undefined,
    };

    if (existing) await window.vaultAPI.updateTotpEntry(existing.id, payload);
    else await window.vaultAPI.addTotpEntry(payload as Omit<TwoFactorEntry, 'id' | 'createdAt' | 'updatedAt'>);

    setEditor(null);
    await loadEntries();
    await refreshCodes();
    notify('success', existing ? 'Account updated' : 'Account added');
  }, [loadEntries, refreshCodes, notify]);

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter((e) =>
      [e.title, e.issuer, e.account, ...(e.domains || [])]
        .filter(Boolean)
        .some((field) => String(field).toLowerCase().includes(q))
    );
  }, [entries, search]);

  const canReorder = !search.trim();

  const handleDrop = useCallback(async (targetId: string) => {
    setDropId(null);
    const sourceId = dragId;
    setDragId(null);
    if (!sourceId || sourceId === targetId) return;

    const ids = entries.map((e) => e.id);
    const from = ids.indexOf(sourceId);
    const to = ids.indexOf(targetId);
    if (from < 0 || to < 0) return;

    ids.splice(from, 1);
    ids.splice(to, 0, sourceId);

    // Optimistic: reorder locally so the card lands instantly, then persist.
    const byId = new Map(entries.map((e) => [e.id, e]));
    setEntries(ids.map((id) => byId.get(id)!).filter(Boolean));

    try {
      const updated = await window.vaultAPI.reorderTotpEntries(ids);
      setEntries(sortEntries(updated));
    } catch (err: any) {
      notify('error', err?.message || 'Could not save the new order');
      await loadEntries();
    }
  }, [dragId, entries, loadEntries, notify]);

  return (
    <div className="space-y-5 animate-fade-in">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Authenticator</h1>
          <p className="text-gray-400 text-sm mt-1">
            {entries.length === 0
              ? 'No accounts yet'
              : `${entries.length} account${entries.length === 1 ? '' : 's'}${
                  visible.length !== entries.length ? ` • ${visible.length} shown` : ''
                }`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setImportOpen(true)} className="btn-secondary flex items-center gap-2 text-sm">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            Import
          </button>
          <button onClick={() => setEditor({ entry: null })} className="btn-primary flex items-center gap-2 text-sm">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Add account
          </button>
        </div>
      </header>

      {banner && (
        <div
          className={`rounded-xl px-4 py-3 text-sm border flex items-start gap-2 ${
            banner.kind === 'error'
              ? 'bg-red-500/10 border-red-500/30 text-red-300'
              : 'bg-green-500/10 border-green-500/30 text-green-300'
          }`}
        >
          <span aria-hidden>{banner.kind === 'error' ? '✕' : '✓'}</span>
          <span>{banner.text}</span>
        </div>
      )}

      <div className="relative">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-field pl-12"
          placeholder="Search by issuer, account or site…"
          aria-label="Search accounts"
        />
      </div>

      {loading ? (
        <div className="glass-card p-12 flex flex-col items-center gap-3">
          <div className="spinner" />
          <p className="text-sm text-gray-400">Loading accounts…</p>
        </div>
      ) : visible.length === 0 ? (
        <EmptyState
          searching={!!search.trim()}
          onAdd={() => setEditor({ entry: null })}
          onImport={() => setImportOpen(true)}
        />
      ) : (
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3">
          {visible.map((entry) => (
            <TotpCard
              key={entry.id}
              entry={entry}
              result={codes[entry.id]}
              nowSec={nowSec}
              copied={copiedId === entry.id}
              draggable={canReorder}
              isDragging={dragId === entry.id}
              isDropTarget={dropId === entry.id && dragId !== entry.id}
              onDragStart={() => setDragId(entry.id)}
              onDragEnd={() => { setDragId(null); setDropId(null); }}
              onDragOver={() => setDropId(entry.id)}
              onDrop={() => handleDrop(entry.id)}
              onCopy={handleCopy}
              onEdit={() => setEditor({ entry })}
              onDelete={() => handleDelete(entry)}
              onTogglePin={() => handleTogglePin(entry)}
              onIncrement={() => handleIncrementHotp(entry)}
              onShowQr={() => handleShowQr(entry)}
            />
          ))}
        </div>
      )}

      {editor && (
        <EntryEditor
          entry={editor.entry}
          onClose={() => setEditor(null)}
          onSave={(draft) => handleSave(draft, editor.entry)}
        />
      )}

      {importOpen && (
        <ImportModal
          onClose={() => setImportOpen(false)}
          onDone={async (message) => {
            setImportOpen(false);
            await loadEntries();
            await refreshCodes();
            notify('success', message);
          }}
        />
      )}

      {qr && <QrModal {...qr} onClose={() => setQr(null)} />}
    </div>
  );
}

// ============================================
// Card
// ============================================

function TotpCard({
  entry, result, nowSec, copied, draggable, isDragging, isDropTarget,
  onDragStart, onDragEnd, onDragOver, onDrop,
  onCopy, onEdit, onDelete, onTogglePin, onIncrement, onShowQr,
}: {
  entry: TwoFactorEntry;
  result?: OtpCodeResult;
  nowSec: number;
  copied: boolean;
  draggable: boolean;
  isDragging: boolean;
  isDropTarget: boolean;
  onDragStart: () => void;
  onDragEnd: () => void;
  onDragOver: () => void;
  onDrop: () => void;
  onCopy: (entry: TwoFactorEntry, code: string) => void;
  onEdit: () => void;
  onDelete: () => void;
  onTogglePin: () => void;
  onIncrement: () => void;
  onShowQr: () => void;
}) {
  const isHotp = entry.type === 'HOTP';
  const period = result?.period || entry.period || 30;
  const digits = result?.digits || entry.digits || 6;
  const code = result?.code || '';
  const hue = avatarHue(entry);

  // Derived from the wall clock rather than a counter, so the label stays
  // correct even if the window was suspended or a render was dropped.
  const remaining = result && result.expiresAt > 0
    ? Math.max(0, Math.ceil((result.expiresAt - nowSec * 1000) / 1000))
    : 0;
  const urgent = !isHotp && remaining > 0 && remaining <= 5;
  const warn = !isHotp && remaining > 5 && remaining <= 10;

  // Negative delay puts the CSS ring animation at the right phase without a
  // per-frame React render. The key below restarts it at each rollover.
  const elapsed = Math.min(period, Math.max(0, period - remaining));

  return (
    <div
      draggable={draggable}
      onDragStart={(e) => { e.dataTransfer.effectAllowed = 'move'; onDragStart(); }}
      onDragEnd={onDragEnd}
      onDragOver={(e) => { if (draggable) { e.preventDefault(); onDragOver(); } }}
      onDrop={(e) => { e.preventDefault(); onDrop(); }}
      className={`glass-card glass-card-hover p-4 transition-all group relative ${
        isDragging ? 'totp-dragging' : ''
      } ${isDropTarget ? 'totp-drop-target' : ''}`}
    >
      <div className="flex items-start gap-3">
        <div
          className="w-10 h-10 shrink-0 rounded-xl flex items-center justify-center font-bold text-base"
          style={{
            background: `hsl(${hue} 70% 55% / 0.18)`,
            color: `hsl(${hue} 80% 72%)`,
            border: `1px solid hsl(${hue} 70% 55% / 0.28)`,
          }}
          aria-hidden
        >
          {avatarLetter(entry)}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <h3 className="font-semibold text-sm truncate">{displayName(entry)}</h3>
            {entry.pinned && (
              <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" className="text-vault-400 shrink-0" aria-label="Pinned">
                <path d="M12 2l2.4 7.4H22l-6 4.6 2.3 7.4L12 16.8 5.7 21.4 8 14 2 9.4h7.6z" />
              </svg>
            )}
          </div>
          <p className="text-xs text-gray-400 truncate">
            {entry.account || entry.title}
          </p>
        </div>

        <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
          <IconButton label={entry.pinned ? 'Unpin' : 'Pin to top'} onClick={onTogglePin}>
            <path d="M12 2l2.4 7.4H22l-6 4.6 2.3 7.4L12 16.8 5.7 21.4 8 14 2 9.4h7.6z" />
          </IconButton>
          <IconButton label="Show QR code" onClick={onShowQr}>
            <rect x="3" y="3" width="7" height="7" />
            <rect x="14" y="3" width="7" height="7" />
            <rect x="3" y="14" width="7" height="7" />
            <path d="M14 14h3v3h-3zM19 19h2v2h-2z" />
          </IconButton>
          <IconButton label="Edit" onClick={onEdit}>
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
          </IconButton>
          <IconButton label="Delete" onClick={onDelete} danger>
            <polyline points="3 6 5 6 21 6" />
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
          </IconButton>
        </div>
      </div>

      {result?.error ? (
        <div className="mt-3 rounded-xl bg-red-500/10 border border-red-500/25 p-3">
          <p className="text-xs text-red-300 font-medium">This secret cannot produce codes</p>
          <p className="text-xs text-red-400/80 mt-1">{result.error}</p>
          <button onClick={onEdit} className="text-xs text-red-300 underline mt-2">Fix the secret</button>
        </div>
      ) : (
        <div className="mt-3 flex items-center gap-3">
          <button
            onClick={() => onCopy(entry, code)}
            disabled={!code}
            title="Copy code"
            className="flex-1 min-w-0 text-left rounded-xl bg-dark-bg/60 px-3 py-2.5 hover:bg-vault-500/10 transition-colors disabled:cursor-not-allowed"
          >
            <span
              key={`${code}-${result?.expiresAt ?? 0}`}
              className={`code-swap totp-code block text-2xl font-bold tabular-nums ${
                urgent ? 'text-red-300' : warn ? 'text-amber-300' : 'text-vault-300'
              }`}
            >
              {result ? formatCode(code, digits) : '•'.repeat(digits)}
            </span>
            <span className="block text-[11px] text-gray-500 mt-0.5">
              {copied ? (
                <span className="text-green-400">✓ Copied to clipboard</span>
              ) : isHotp ? (
                `HOTP • counter ${result?.counter ?? entry.counter ?? 0}`
              ) : remaining > 0 && remaining <= 8 && result?.nextCode ? (
                <>next <span className="totp-code text-gray-400">{formatCode(result.nextCode, digits)}</span></>
              ) : (
                'Click to copy'
              )}
            </span>
          </button>

          {isHotp ? (
            <button
              onClick={onIncrement}
              title="Generate the next code"
              aria-label="Generate the next code"
              className="w-11 h-11 shrink-0 rounded-full border border-vault-500/30 bg-vault-500/10 text-vault-300 flex items-center justify-center hover:bg-vault-500/20 transition-colors"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <polyline points="23 4 23 10 17 10" />
                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
              </svg>
            </button>
          ) : (
            <CountdownRing
              // Restarting on rollover re-seeds the animation phase, which is
              // what keeps the ring smooth without per-frame renders.
              key={`${result?.expiresAt ?? 0}`}
              period={period}
              elapsed={elapsed}
              remaining={remaining}
              urgent={urgent}
              warn={warn}
              stalled={!result}
            />
          )}
        </div>
      )}

      <p className="mt-2 text-[11px] text-gray-600 truncate">
        {entry.steam ? 'Steam' : entry.type} • {entry.algorithm || 'SHA1'} • {entry.steam ? 5 : digits} digits
        {!isHotp && ` • ${period}s`}
      </p>
    </div>
  );
}

function CountdownRing({ period, elapsed, remaining, urgent, warn, stalled }: {
  period: number;
  elapsed: number;
  remaining: number;
  urgent: boolean;
  warn: boolean;
  stalled: boolean;
}) {
  // Snapshot the phase at mount. `animation-delay` is measured from when the
  // animation started, so re-applying a fresh elapsed value on every render
  // would add the same time twice and run the ring fast. The parent remounts
  // this component at each rollover, which is when the phase should reset.
  const [phaseDelay] = useState(() => elapsed);
  const color = urgent ? '#fca5a5' : warn ? '#fcd34d' : '#a78bfa';
  return (
    <div className="relative w-11 h-11 shrink-0" role="timer" aria-label={`${remaining} seconds remaining`}>
      <svg width="44" height="44" viewBox="0 0 36 36" className="block">
        <circle cx="18" cy="18" r={RING_RADIUS} fill="none" stroke="rgba(124,92,255,0.15)" strokeWidth="3" />
        {!stalled && (
          <circle
            cx="18"
            cy="18"
            r={RING_RADIUS}
            fill="none"
            stroke={color}
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray={RING_CIRCUMFERENCE}
            className="totp-ring-fill"
            style={{
              ['--ring-circumference' as any]: `${RING_CIRCUMFERENCE}`,
              ['--totp-period' as any]: `${period}s`,
              ['--totp-delay' as any]: `-${phaseDelay}s`,
            }}
          />
        )}
      </svg>
      <span
        className={`absolute inset-0 flex items-center justify-center text-[11px] font-semibold tabular-nums ${
          urgent ? 'text-red-300' : warn ? 'text-amber-300' : 'text-gray-400'
        }`}
      >
        {stalled ? '—' : remaining}
      </span>
    </div>
  );
}

function IconButton({ label, onClick, danger, children }: {
  label: string;
  onClick: () => void;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      aria-label={label}
      className={`p-1.5 rounded-lg text-gray-500 transition-colors ${
        danger ? 'hover:bg-red-500/20 hover:text-red-400' : 'hover:bg-dark-hover hover:text-vault-300'
      }`}
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        {children}
      </svg>
    </button>
  );
}

function EmptyState({ searching, onAdd, onImport }: {
  searching: boolean;
  onAdd: () => void;
  onImport: () => void;
}) {
  if (searching) {
    return (
      <div className="glass-card p-12 text-center">
        <p className="text-gray-400">No accounts match your search</p>
      </div>
    );
  }
  return (
    <div className="glass-card p-12 text-center">
      <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mx-auto mb-4 text-gray-600">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
      <p className="text-gray-300 font-medium">No 2FA accounts yet</p>
      <p className="text-sm text-gray-500 mt-1 max-w-md mx-auto">
        Paste an <span className="font-mono text-gray-400">otpauth://</span> link from a
        site's setup page, import an export from Google Authenticator, or type a secret in
        by hand.
      </p>
      <div className="flex items-center justify-center gap-2 mt-5">
        <button onClick={onImport} className="btn-secondary text-sm">Import a link</button>
        <button onClick={onAdd} className="btn-primary text-sm">Add manually</button>
      </div>
    </div>
  );
}

// ============================================
// Add / edit
// ============================================

function EntryEditor({ entry, onClose, onSave }: {
  entry: TwoFactorEntry | null;
  onClose: () => void;
  onSave: (draft: Draft) => Promise<void>;
}) {
  const [draft, setDraft] = useState<Draft>(() => (entry ? draftFrom(entry) : emptyDraft()));
  const [secretCheck, setSecretCheck] = useState<{ valid: boolean; error?: string; keyBytes?: number } | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [showSecret, setShowSecret] = useState(!entry);

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) =>
    setDraft((prev) => ({ ...prev, [key]: value }));

  // Validate through the same code path that will store the secret, so the
  // form can never accept something the vault would reject.
  useEffect(() => {
    const raw = draft.secret.replace(/\s+/g, '');
    if (!raw) { setSecretCheck(null); return; }
    let alive = true;
    const timer = window.setTimeout(() => {
      window.vaultAPI
        .validateSecret(raw, draft.encoding)
        .then((res) => { if (alive) setSecretCheck(res); })
        .catch(() => { if (alive) setSecretCheck(null); });
    }, 200);
    return () => { alive = false; window.clearTimeout(timer); };
  }, [draft.secret, draft.encoding]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    setSaving(true);
    try {
      await onSave(draft);
    } catch (err: any) {
      setSaveError(err?.message || 'Could not save the account');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={entry ? 'Edit account' : 'Add account'} onClose={onClose} wide>
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <Field label="Issuer" hint="The service, e.g. GitHub">
            <input
              type="text"
              value={draft.issuer}
              onChange={(e) => set('issuer', e.target.value)}
              className="input-field"
              placeholder="GitHub"
              autoFocus
            />
          </Field>
          <Field label="Account" hint="Your username on that service">
            <input
              type="text"
              value={draft.account}
              onChange={(e) => set('account', e.target.value)}
              className="input-field"
              placeholder="you@example.com"
            />
          </Field>
        </div>

        <Field label="Label" hint="Shown when no issuer is set">
          <input
            type="text"
            value={draft.title}
            onChange={(e) => set('title', e.target.value)}
            className="input-field"
            placeholder={draft.issuer || 'My account'}
          />
        </Field>

        <Field label="Secret key" hint="Exactly as the service gave it to you — spaces are ignored">
          <div className="relative">
            <input
              type={showSecret ? 'text' : 'password'}
              value={draft.secret}
              onChange={(e) => set('secret', e.target.value)}
              className="input-field pr-32 font-mono"
              placeholder="JBSWY3DPEHPK3PXP"
              spellCheck={false}
              autoComplete="off"
              required
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
              <button
                type="button"
                onClick={() => setShowSecret((v) => !v)}
                className="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200"
              >
                {showSecret ? 'Hide' : 'Show'}
              </button>
              <button
                type="button"
                onClick={async () => set('secret', await window.vaultAPI.generateSecret())}
                className="px-2 py-1 rounded text-xs bg-vault-500/20 text-vault-300 hover:bg-vault-500/30"
              >
                Generate
              </button>
            </div>
          </div>
          {secretCheck && (
            <p className={`text-xs mt-1.5 ${secretCheck.valid ? 'text-green-400' : 'text-red-400'}`}>
              {secretCheck.valid
                ? `✓ Valid ${draft.encoding} secret (${secretCheck.keyBytes} bytes)`
                : `✕ ${secretCheck.error}`}
            </p>
          )}
        </Field>

        <div className="grid grid-cols-4 gap-3">
          <Field label="Type">
            <select value={draft.type} onChange={(e) => set('type', e.target.value as Draft['type'])} className="input-field">
              <option value="TOTP">Time based</option>
              <option value="HOTP">Counter based</option>
            </select>
          </Field>
          <Field label="Algorithm">
            <select value={draft.algorithm} onChange={(e) => set('algorithm', e.target.value as Draft['algorithm'])} className="input-field">
              <option value="SHA1">SHA1</option>
              <option value="SHA256">SHA256</option>
              <option value="SHA512">SHA512</option>
            </select>
          </Field>
          <Field label="Digits">
            <select
              value={draft.digits}
              onChange={(e) => set('digits', parseInt(e.target.value, 10))}
              className="input-field"
              disabled={draft.steam}
            >
              <option value={6}>6</option>
              <option value={7}>7</option>
              <option value={8}>8</option>
            </select>
          </Field>
          {draft.type === 'TOTP' ? (
            <Field label="Period">
              <select value={draft.period} onChange={(e) => set('period', parseInt(e.target.value, 10))} className="input-field">
                <option value={15}>15s</option>
                <option value={30}>30s</option>
                <option value={60}>60s</option>
              </select>
            </Field>
          ) : (
            <Field label="Counter">
              <input
                type="number"
                min={0}
                value={draft.counter}
                onChange={(e) => set('counter', Math.max(0, parseInt(e.target.value || '0', 10)))}
                className="input-field"
              />
            </Field>
          )}
        </div>

        <details className="rounded-xl border border-dark-border/80 px-4 py-3">
          <summary className="text-sm text-gray-300 cursor-pointer select-none">Advanced</summary>
          <div className="mt-4 space-y-4">
            <Field label="Secret encoding" hint="Base32 unless the service says otherwise">
              <select value={draft.encoding} onChange={(e) => set('encoding', e.target.value as Draft['encoding'])} className="input-field">
                <option value="base32">Base32 (standard)</option>
                <option value="hex">Hexadecimal</option>
                <option value="ascii">Raw ASCII</option>
              </select>
            </Field>
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={draft.steam}
                onChange={(e) => set('steam', e.target.checked)}
                className="mt-1"
              />
              <span className="text-sm">
                Steam Guard
                <span className="block text-xs text-gray-500">
                  Produces 5-character codes from Steam's own alphabet instead of digits.
                </span>
              </span>
            </label>
            <Field label="Notes">
              <textarea
                value={draft.notes}
                onChange={(e) => set('notes', e.target.value)}
                className="input-field h-20 resize-none"
                placeholder="Recovery codes are in the safe…"
              />
            </Field>
          </div>
        </details>

        {saveError && (
          <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/25 rounded-lg px-3 py-2">{saveError}</p>
        )}

        <div className="flex justify-end gap-3 pt-1">
          <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
          <button
            type="submit"
            disabled={saving || (secretCheck ? !secretCheck.valid : false)}
            className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? 'Saving…' : entry ? 'Save changes' : 'Add account'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ============================================
// Import
// ============================================

function ImportModal({ onClose, onDone }: {
  onClose: () => void;
  onDone: (message: string) => Promise<void>;
}) {
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const run = async () => {
    if (!input.trim()) return;
    setBusy(true);
    setErrors([]);
    try {
      const result = await window.vaultAPI.importOtpUris(input);
      if (result.imported > 0) {
        const parts = [`Imported ${result.imported} account${result.imported === 1 ? '' : 's'}`];
        if (result.skipped) parts.push(`${result.skipped} already present`);
        if (result.errors.length) parts.push(`${result.errors.length} failed`);
        await onDone(parts.join(' • '));
        return;
      }
      setErrors(
        result.errors.length
          ? result.errors
          : [result.skipped ? 'Every account in that link is already in your vault.' : 'Nothing could be imported.']
      );
    } catch (err: any) {
      setErrors([err?.message || 'Import failed']);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Import accounts" onClose={onClose} wide>
      <div className="space-y-4">
        <p className="text-sm text-gray-400">
          Paste one or more links, one per line. Both single{' '}
          <span className="font-mono text-gray-300">otpauth://</span> links and the{' '}
          <span className="font-mono text-gray-300">otpauth-migration://</span> export that
          Google Authenticator produces are supported.
        </p>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          className="input-field h-36 resize-none font-mono text-xs"
          placeholder={'otpauth://totp/GitHub:you@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\notpauth-migration://offline?data=…'}
          spellCheck={false}
          autoFocus
        />
        {errors.length > 0 && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/25 px-3 py-2 max-h-32 overflow-auto">
            {errors.map((message, i) => (
              <p key={i} className="text-xs text-red-300">{message}</p>
            ))}
          </div>
        )}
        <div className="flex justify-end gap-3">
          <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
          <button onClick={run} disabled={busy || !input.trim()} className="btn-primary disabled:opacity-50">
            {busy ? 'Importing…' : 'Import'}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ============================================
// QR
// ============================================

function QrModal({ title, uri, dataUrl, onClose }: {
  title: string;
  uri: string;
  dataUrl: string;
  onClose: () => void;
}) {
  const [revealed, setRevealed] = useState(false);
  return (
    <Modal title={`Move "${title}" to another device`} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-amber-300 bg-amber-500/10 border border-amber-500/25 rounded-lg px-3 py-2">
          This QR code contains the account's secret. Anyone who photographs it can generate
          your codes.
        </p>
        <div className="flex justify-center">
          <img src={dataUrl} alt="" className="rounded-xl bg-white p-3 w-56 h-56" />
        </div>
        <div>
          <button
            onClick={() => setRevealed((v) => !v)}
            className="text-xs text-gray-400 hover:text-gray-200 underline"
          >
            {revealed ? 'Hide the raw link' : 'Show the raw link'}
          </button>
          {revealed && (
            <div className="mt-2 flex items-start gap-2">
              <code className="flex-1 text-[11px] break-all bg-dark-bg/70 rounded-lg p-2 text-gray-400">{uri}</code>
              <button
                onClick={() => window.vaultAPI.copyToClipboard(uri)}
                className="btn-secondary text-xs shrink-0"
              >
                Copy
              </button>
            </div>
          )}
        </div>
        <div className="flex justify-end">
          <button onClick={onClose} className="btn-primary">Done</button>
        </div>
      </div>
    </Modal>
  );
}

// ============================================
// Shared bits
// ============================================

function Modal({ title, onClose, wide, children }: {
  title: string;
  onClose: () => void;
  wide?: boolean;
  children: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-6 modal-backdrop" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`glass-card w-full ${wide ? 'max-w-xl' : 'max-w-md'} p-6 animate-slide-in max-h-[88vh] overflow-auto`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 mb-5">
          <h2 className="text-lg font-bold">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="p-1.5 rounded-lg hover:bg-dark-hover text-gray-400 hover:text-white shrink-0">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function Field({ label, hint, children }: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="block text-sm text-gray-300 mb-1">{label}</span>
      {children}
      {hint && <span className="block text-[11px] text-gray-500 mt-1">{hint}</span>}
    </label>
  );
}
