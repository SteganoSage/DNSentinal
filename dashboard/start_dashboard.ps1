# PowerShell Runner for DNSentinel Cybersecurity Dashboard
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "   DNSentinel - Secure Recursive DNS Resolver Dashboard" -ForegroundColor Cyan
Write-Host "   Mode: DEMO / SAMPLE DATA (Safe Sandbox Mode)" -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$ScriptDir\backend"

Write-Host "Opening dashboard in default web browser: http://127.0.0.1:8000" -ForegroundColor Green
Start-Process "http://127.0.0.1:8000"

Write-Host "Starting FastAPI backend server..." -ForegroundColor Green
py run_backend.py
