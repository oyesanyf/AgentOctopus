@echo off
setlocal
cd /d "%~dp0"
echo ========================================================
echo   HTTP TERMINATOR: BUILD ALL AUTOMATION LAUNCHER
echo ========================================================
python build_all.py %*
if %ERRORLEVEL% NEQ 0 (
    echo [!] Build failed with exit code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)
echo [+] Build completed successfully.
exit /b 0
