@echo off
echo =========================================
echo Web Security Checker - Azure IIS Edition
echo =========================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0web-security-checker\scripts\scan_targets.ps1"
echo.
echo Scanning complete. Check Security_Report.md
pause