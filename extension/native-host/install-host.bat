@echo off
setlocal enabledelayedexpansion
echo ============================================
echo  VaultGuard Native Messaging Host Setup
echo ============================================
echo.

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"

echo Step 1: Copying native host files to AppData...

:: Create installation directory
set "INSTALL_DIR=%APPDATA%\VaultGuard\native-host"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: Copy all native host files
copy /y "%SCRIPT_DIR%com.vaultguard.native.json" "%INSTALL_DIR%\" >nul 2>&1
copy /y "%SCRIPT_DIR%vaultguard-native-host.bat" "%INSTALL_DIR%\" >nul 2>&1
copy /y "%SCRIPT_DIR%vaultguard-native-host.js" "%INSTALL_DIR%\" >nul 2>&1

set "INSTALL_JSON=%INSTALL_DIR%\com.vaultguard.native.json"
echo   [OK] Files copied to %INSTALL_DIR%

echo.
echo Step 2: Setting up extension permissions...
echo.
echo   To find your Extension ID:
echo   1. Open chrome://extensions
echo   2. Enable Developer mode (top-right toggle)
echo   3. Copy the ID shown under VaultGuard
echo.
set /p EXTENSION_ID="Paste your Extension ID here: "

if "%EXTENSION_ID%"=="" (
    echo   ERROR: Extension ID cannot be empty
    pause
    exit /b 1
)

:: Create the JSON with the correct extension ID
(
echo {
echo   "name": "com.vaultguard.native",
echo   "description": "VaultGuard Native Messaging Host",
echo   "path": "vaultguard-native-host.bat",
echo   "type": "stdio",
echo   "allowed_origins": [
echo     "chrome-extension://%EXTENSION_ID%/"
echo   ]
echo }
) > "%INSTALL_JSON%"
echo   [OK] Manifest updated with extension ID: %EXTENSION_ID%

echo.
echo Step 3: Registering native messaging host...

:: Register for Chrome (HKCU = current user, no admin needed)
reg add "HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vaultguard.native" /ve /t REG_SZ /d "%INSTALL_JSON%" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] Chrome registered successfully
) else (
    echo   [FAIL] Chrome registration failed
)

:: Register for Microsoft Edge
reg add "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.vaultguard.native" /ve /t REG_SZ /d "%INSTALL_JSON%" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] Edge registered successfully
) else (
    echo   [FAIL] Edge registration failed
)

:: Register for Brave (optional)
reg add "HKCU\Software\Brave\Brave\NativeMessagingHosts\com.vaultguard.native" /ve /t REG_SZ /d "%INSTALL_JSON%" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] Brave registered successfully
) else (
    echo   [INFO] Brave not installed, skipping
)

echo.
echo ============================================
echo  Setup Complete!
echo ============================================
echo.
echo  1. Restart your browser
echo  2. Click "Retry" in the VaultGuard extension
echo  3. The extension should now connect to the desktop app
echo.
pause
