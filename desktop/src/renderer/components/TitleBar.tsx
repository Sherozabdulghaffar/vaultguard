import React, { useEffect, useState } from 'react';

interface TitleBarProps {
  onLock: () => void;
}

/**
 * The window is frameless on Windows/Linux (and uses `hiddenInset` on macOS),
 * so this bar has to provide the real window controls. On macOS the native
 * traffic lights are still drawn by the OS, so we leave room for them instead
 * of painting our own.
 */
export default function TitleBar({ onLock }: TitleBarProps) {
  const isMac = window.vaultAPI?.platform === 'darwin';
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    window.vaultAPI?.isWindowMaximized?.().then(setMaximized).catch(() => {});
    return window.vaultAPI?.onWindowStateChanged?.((state) => setMaximized(state.maximized));
  }, []);

  return (
    <div className="h-10 shrink-0 bg-dark-bg/95 border-b border-dark-border flex items-center justify-between titlebar-drag select-none">
      <div className={`flex items-center gap-2.5 ${isMac ? 'pl-20' : 'pl-3'}`}>
        <div className="w-5 h-5 rounded-md bg-gradient-to-br from-vault-500 to-vault-700 flex items-center justify-center">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-white">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        </div>
        <span className="font-semibold text-[13px] tracking-tight">VaultGuard</span>
      </div>

      <div className="flex items-center titlebar-no-drag h-full">
        <button
          onClick={onLock}
          className="h-full px-3 flex items-center text-gray-400 hover:text-vault-300 hover:bg-vault-500/10 transition-colors"
          title="Lock vault (Ctrl+L)"
          aria-label="Lock vault"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        </button>

        {!isMac && (
          <>
            <WindowButton label="Minimize" onClick={() => window.vaultAPI.minimizeWindow()}>
              <rect x="4" y="9.5" width="12" height="1" />
            </WindowButton>

            <WindowButton
              label={maximized ? 'Restore' : 'Maximize'}
              onClick={async () => setMaximized(await window.vaultAPI.toggleMaximizeWindow())}
            >
              {maximized ? (
                <>
                  <rect x="6.5" y="4.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1" />
                  <path d="M4.5 6.5 L4.5 15.5 L13.5 15.5" fill="none" stroke="currentColor" strokeWidth="1" />
                </>
              ) : (
                <rect x="5" y="5" width="10" height="10" fill="none" stroke="currentColor" strokeWidth="1" />
              )}
            </WindowButton>

            <button
              onClick={() => window.vaultAPI.closeWindow()}
              className="h-full w-12 flex items-center justify-center text-gray-400 hover:text-white hover:bg-red-600 transition-colors"
              title="Close to tray"
              aria-label="Close window"
            >
              <svg width="20" height="20" viewBox="0 0 20 20" stroke="currentColor" strokeWidth="1" fill="none">
                <path d="M5.5 5.5 L14.5 14.5 M14.5 5.5 L5.5 14.5" />
              </svg>
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function WindowButton({ label, onClick, children }: {
  label: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className="h-full w-12 flex items-center justify-center text-gray-400 hover:text-white hover:bg-dark-hover transition-colors"
      title={label}
      aria-label={label}
    >
      <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
        {children}
      </svg>
    </button>
  );
}
