@echo off
title DNSentinel Cybersecurity Dashboard
echo =====================================================================
echo    DNSentinel - Secure Recursive DNS Resolver Dashboard
echo    Mode: DEMO / SAMPLE DATA
echo =====================================================================
echo.
echo [1/2] Checking Python environment...
py --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not found. Please ensure Python is installed.
    pause
    exit /b 1
)

echo [2/2] Launching DNSentinel Dashboard server at http://127.0.0.1:8000 ...
start http://127.0.0.1:8000

cd /d "%~dp0\backend"
py run_backend.py
pause
