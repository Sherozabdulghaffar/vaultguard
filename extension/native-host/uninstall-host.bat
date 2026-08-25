@echo off
echo ============================================
echo  VaultGuard Native Messaging Host Removal
echo ============================================
echo.

:: Unregister from Chrome
echo Unregistering from Google Chrome...
reg delete "HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vaultguard.native" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] Chrome unregistered
) else (
    echo   [INFO] Chrome entry not found
)

:: Unregister from Edge
echo Unregistering from Microsoft Edge...
reg delete "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.vaultguard.native" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] Edge unregistered
) else (
    echo   [INFO] Edge entry not found
)

:: Unregister from Brave
echo Unregistering from Brave Browser...
reg delete "HKCU\Software\Brave\Brave\NativeMessagingHosts\com.vaultguard.native" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] Brave unregistered
) else (
    echo   [INFO] Brave entry not found
)

echo.
echo ============================================
echo  Removal Complete!
echo ============================================
echo.
echo  Restart your browser for changes to take effect.
echo.
pause
