# VaultGuard Browser Extension - Installation Guide

## Quick Install (Developer Mode)

### Chrome / Edge / Brave

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in top-right corner)
3. Click **"Load unpacked"** button (top-left)
4. Navigate to and select the `extension` folder inside the VaultGuard project
5. The VaultGuard icon will appear in your browser toolbar
6. **Copy the Extension ID** shown under VaultGuard (you'll need it next)

### Firefox

1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
2. Click **"Load Temporary Add-on..."**
3. Select the `manifest.json` file inside the `extension` folder
4. The VaultGuard icon will appear in your browser toolbar

## Native Messaging Host Setup (Required!)

The extension communicates with the VaultGuard desktop app via **Native Messaging**. This requires a one-time setup:

1. Navigate to `extension/native-host/` in your project
2. Double-click `install-host.bat` to run it
3. When prompted, paste your **Extension ID** from step 6 above
4. The script will:
   - Copy native host files to `%APPDATA%\VaultGuard\native-host\`
   - Register the native messaging host in Windows Registry for Chrome, Edge, and Brave
5. **Restart your browser** for changes to take effect
6. Click the VaultGuard extension icon and click **"Retry"** if needed

### Uninstalling the Native Host

Run `extension/native-host/uninstall-host.bat` to remove the Registry entries.

## First-Time Setup

1. **Install the desktop app first** — Start VaultGuard and create a master password
2. **Install the extension** — Follow the steps above
3. **Run the native host installer** — `extension/native-host/install-host.bat`
4. **Restart your browser** — The extension will auto-connect to the desktop app
5. **Use auto-fill** — Visit any login page and the extension will detect password fields

## Features

- **Auto-fill passwords** — Detects login forms and offers to fill credentials
- **2FA code detection** — Scans pages for TOTP setup QR codes and secrets
- **Biometric unlock** — Use Windows Hello to unlock the vault from the extension
- **Secure communication** — All data flows through the desktop app (never sent to external servers)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Extension shows "Disconnected" | Make sure VaultGuard desktop app is running |
| "Native host not registered" | Run `install-host.bat` and restart browser |
| Auto-fill not working | Check that "Auto-fill on page load" is enabled in Settings |
| Extension not detecting 2FA | Some sites use non-standard 2FA — manual entry is always available |
| Badge shows red ✕ | Native host not registered or desktop app not running |
| Badge shows yellow 🔒 | Desktop connected but vault is locked — unlock in the extension popup |
