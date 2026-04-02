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

### 4. Nuclei 廣度弱點掃描 (擴充功能)
使用 `nuclei.exe` 進行自動化弱點掃描：
- **檢查範疇**：包含配置錯誤 (misconfig)、敏感資訊外洩 (exposure)、控制台外洩 (panel) 及技術棧偵測 (tech)。
- **自動整合**：掃描結果將自動彙整至報告末尾的弱點清單。

## 掃描模式 (Scan Modes)

此工具支援兩種掃描模式：

### 1. Simple 模式 (預設)
- **執行指令**: `Run-SecurityScan.bat` (不帶參數)
- **檢查項目**: 基本安全標頭 (HSTS, XFO, XCTO)、TLS 版本、弱加密套件、TRACE、敏感檔案。
- **特點**: 掃描速度快，適合日常例行檢查。

### 2. Full 模式
- **執行指令**: `Run-SecurityScan.bat Full`
- **檢查項目**: 包含 Simple 模式的所有項目，並額外執行 **Nuclei** 廣度弱點掃描。
- **特點**: 檢查更全面，包含配置錯誤 (misconfig)、敏感資訊外洩 (exposure) 等，適合定期深度稽核。

## 執行指令建議

### 執行單一網址檢查
「請使用 web-security-checker 檢查 [網址]」

### 執行自動化清單檢查
- **預設模式 (Simple)**: 「請執行 web-security-checker 掃描清單」
- **完整模式 (Full)**: 「請執行 web-security-checker 掃描清單 (Full)」

## 工具建議
在 Windows 環境下，請確保使用 `curl.exe` 進行檢查。若執行自動化腳本，請使用 `powershell.exe -ExecutionPolicy Bypass` 以確保腳本能順利執行。
