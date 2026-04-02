<#
.SYNOPSIS
    執行 Azure Web App (IIS) 網站安全掃描
.DESCRIPTION
    此腳本自動呼叫 web-security-checker 並讀取 targets.txt 來產生 Security_Report.md
#>
param(
    [ValidateSet("Simple", "Full")]
    [string]$ScanMode = "Simple"
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Web Security Checker - Azure IIS Edition " -ForegroundColor Cyan
Write-Host " Mode: $ScanMode" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

$ScriptPath = Join-Path $PSScriptRoot "web-security-checker\scripts\scan_targets.ps1"

if (-not (Test-Path $ScriptPath)) {
    Write-Host "找不到掃描核心程式，請確認 web-security-checker 目錄存在。" -ForegroundColor Red
    exit
}

# 以 Bypass 權限執行掃描腳本
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ScanMode $ScanMode

Write-Host ""
Write-Host "執行完畢。請查看 Security_Report.md 獲取最新報告及修復代碼。" -ForegroundColor Green