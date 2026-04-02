@echo off
set "MODE=Simple"
if /I "%~1"=="Full" set "MODE=Full"

echo =========================================
echo Web Security Checker - Azure IIS Edition
echo Mode: %MODE%
echo =========================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0web-security-checker\scripts\scan_targets.ps1" -ScanMode %MODE%
echo.
echo Scanning complete. Check Security_Report.md
pause