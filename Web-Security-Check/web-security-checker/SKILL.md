---
name: web-security-checker
description: 檢查網站的常見資安漏洞，包括 HSTS、ASP.NET/IIS 版本外洩及 TLS 最低版本支援度。支援清單自動化掃描並輸出 Markdown 表格報告。
---

# Web Security Checker

此 Skill 提供一套標準且自動化的流程，用於檢查網頁伺服器的常見配置漏洞。

## 核心功能與檢查項目

### 1. 安全標頭檢查
使用 `curl.exe -I -L` 分析回應標頭：
- **HSTS (Strict-Transport-Security)**：確認是否強制 HTTPS。
- **ASP.NET 版本 (X-AspNet-Version / X-Powered-By)**：確認是否外洩框架版本。
- **IIS/Server 版本 (Server)**：確認是否外洩伺服器軟體版本。

### 2. TLS 版本相容性檢查 (最低支援版本)
使用 `curl.exe` 強制指定 TLS 版本連線，以確認伺服器支援度：
- **TLS 1.1**：檢查是否仍支援此過時版本（建議不支援）。
- **TLS 1.2**：目前主流支援版本。
- **TLS 1.3**：目前最安全的新一代傳輸協議。

### 3. 自動化掃描清單
Skill 內建自動化腳本，可批次處理多個網域。
- **清單檔案**：`targets.txt` (每行一個網域)。
- **自動腳本**：`web-security-checker\scripts\scan_targets.ps1`。
- **輸出格式**：自動彙整為 Markdown 表格。

## 執行指令建議

### 執行單一網址檢查
「請使用 web-security-checker 檢查 [網址]」

### 執行自動化清單檢查
「請執行 web-security-checker 掃描清單」

## 工具建議
在 Windows 環境下，請確保使用 `curl.exe` 進行檢查。若執行自動化腳本，請使用 `powershell.exe -ExecutionPolicy Bypass` 以確保腳本能順利執行。
