@echo off
:: VaultGuard Native Messaging Host
:: This script bridges Chrome/Edge native messaging to the VaultGuard desktop app
:: It reads JSON messages from stdin (Chrome) and writes JSON responses to stdout

:: Find Node.js or use the desktop app's bundled Node
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo {"error": "Node.js not found. Please install VaultGuard desktop app."}
    exit /b 1
)

:: Path to the native host JS file (same directory as this bat)
set "HOST_DIR=%~dp0"
node "%HOST_DIR%vaultguard-native-host.js"
