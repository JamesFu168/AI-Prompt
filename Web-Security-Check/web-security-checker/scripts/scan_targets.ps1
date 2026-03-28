param(
    [string]$TargetFile = 'targets.txt',
    [string]$OutFile = 'Security_Report.md'
)
$Targets = Get-Content $TargetFile | Where-Object { $_ -and -not $_.StartsWith('#') }
$Results = @()
$FailedTypes = @{}

# 內部邏輯使用純英數字避免 PowerShell 直譯器編碼錯誤
$Pass = 'PASS'
$Fail = 'FAIL'

foreach ($Target in $Targets) {
    $CleanTarget = $Target.Trim()
    if (-not $CleanTarget) { continue }
    $Url = "https://$CleanTarget"
    
    $Headers = curl.exe -s -I -L $Url 2>$null
    
    $Hsts = if ($Headers | Select-String 'Strict-Transport-Security') { $Pass } else { $FailedTypes['HSTS']=$true; $Fail }
    $Xfo = if ($Headers | Select-String 'X-Frame-Options') { $Pass } else { $FailedTypes['XFO']=$true; $Fail }
    $Xcto = if ($Headers | Select-String 'X-Content-Type-Options') { $Pass } else { $FailedTypes['XCTO']=$true; $Fail }
    $Leak = if ($Headers | Select-String 'X-AspNet-Version|X-Powered-By|^Server: (.+\d)') { $FailedTypes['LEAK']=$true; $Fail } else { $Pass }

    $MinTLS = "1.2+"
    curl.exe --tlsv1.1 --tls-max 1.1 -I -s $Url | Out-Null
    if ($LASTEXITCODE -eq 0) { $MinTLS = "1.1(W)"; $FailedTypes['TLS']=$true }
    
    $NmapOut = nmap --script ssl-enum-ciphers -p 443 $CleanTarget 2>$null
    $WF = @()
    if ($NmapOut | Select-String '_MD5') { $WF += 'MD5' }
    if ($NmapOut | Select-String '_CBC') { $WF += 'CBC' }
    if ($NmapOut | Select-String '_SHA ') { $WF += 'SHA1' }
    $Weak = if ($WF.Count -gt 0) { $FailedTypes['WEAK']=$true; "FAIL ($($WF -join ','))" } else { $Pass }

    $Trace = if (curl.exe -X TRACE -I -s $Url | Select-String '200 OK') { $FailedTypes['TRACE']=$true; $Fail } else { $Pass }
    $EnvF = if (curl.exe -s -I "$Url/.env" | Select-String '200 OK') { 'ENV' } else { 'OK' }
    $GitF = if (curl.exe -s -I "$Url/.git/config" | Select-String '200 OK') { 'GIT' } else { 'OK' }
    $Files = if ($EnvF -eq 'OK' -and $GitF -eq 'OK') { $Pass } else { $FailedTypes['FILES']=$true; "FAIL ($EnvF/$GitF)" }

    $Results += [PSCustomObject]@{
        T = $CleanTarget; H = $Hsts; X = "$Xfo / $Xcto"; L = $Leak
        TLS = $MinTLS; W = $Weak; TR = $Trace; F = $Files
    }
}

# 建立 Markdown 內容
$MdContent = @()
$MdContent += "# Web 伺服器安全掃描報告"
$MdContent += "掃描時間: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
$MdContent += ""
$MdContent += "| 目標 (Target) | HSTS | XFO / XCTO | 資訊外洩 (Leak) | TLS 版本 | 弱加密 (Weak) | TRACE | 敏感檔案 (Files) |"
$MdContent += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"

foreach ($R in $Results) {
    # 產出報告時，動態將字串轉換為 Emoji
    $mH = if ($R.H -match 'PASS') { '✅' } else { '❌' }
    $mX = $R.X.Replace('PASS','✅').Replace('FAIL','❌')
    $mL = if ($R.L -match 'PASS') { '✅' } else { '❌' }
    $mTLS = if ($R.TLS -match '1.2\+') { '✅ 1.2+' } else { "❌ $($R.TLS)" }
    $mW = if ($R.W -match 'PASS') { '✅' } else { $R.W.Replace('FAIL','❌') }
    $mTR = if ($R.TR -match 'PASS') { '✅' } else { '❌' }
    $mF = if ($R.F -match 'PASS') { '✅' } else { $R.F.Replace('FAIL','❌') }

    $MdContent += "| $($R.T) | $mH | $mX | $mL | $mTLS | $mW | $mTR | $mF |"
}

$MdContent += ""
if ($FailedTypes.Count -gt 0) {
    $MdContent += "## ❌ 偵測到的弱點與修正建議 (針對 Azure Web App / Windows 環境)"
    $MdContent += ""
    $MdContent += "> **環境註記**：以下建議適用於 Azure Web App (Windows 平台)，請透過專案根目錄的 `"web.config`" 檔案進行調整。"
    $MdContent += ""
}

if ($FailedTypes['HSTS']) {
    $MdContent += "### 1. HSTS (HTTP Strict Transport Security) 缺失"
    $MdContent += "**風險**：使用者可能透過未加密的 HTTP 連線存取網站，容易遭受中間人攻擊。"
    $MdContent += "**修正方式**：在 `"web.config`" 的 `"<customHeaders>`" 中加入標頭。"
    $MdContent += "```xml"
    $MdContent += "<system.webServer>"
    $MdContent += "  <httpProtocol>"
    $MdContent += "    <customHeaders>"
    $MdContent += "      <add name=`"Strict-Transport-Security`" value=`"max-age=31536000; includeSubDomains`" />"
    $MdContent += "    </customHeaders>"
    $MdContent += "  </httpProtocol>"
    $MdContent += "</system.webServer>"
    $MdContent += "```"
    $MdContent += ""
}
if ($FailedTypes['XFO'] -or $FailedTypes['XCTO']) {
    $MdContent += "### 2. XFO / XCTO (安全標頭) 缺失"
    $MdContent += "**風險**：可能導致點擊劫持 (Clickjacking) 與 MIME 類型猜測攻擊。"
    $MdContent += "**修正方式**：於 `"web.config`" 加入 `"X-Frame-Options`" 與 `"X-Content-Type-Options`"。"
    $MdContent += "```xml"
    $MdContent += "<system.webServer>"
    $MdContent += "  <httpProtocol>"
    $MdContent += "    <customHeaders>"
    $MdContent += "      <add name=`"X-Frame-Options`" value=`"SAMEORIGIN`" />"
    $MdContent += "      <add name=`"X-Content-Type-Options`" value=`"nosniff`" />"
    $MdContent += "    </customHeaders>"
    $MdContent += "  </httpProtocol>"
    $MdContent += "</system.webServer>"
    $MdContent += "```"
    $MdContent += ""
}
if ($FailedTypes['LEAK']) {
    $MdContent += "### 3. 資訊外洩 (伺服器/框架版本外洩)"
    $MdContent += "**風險**：伺服器版本或 ASP.NET 版本外洩，使攻擊者能進行針對性攻擊。"
    $MdContent += "**修正方式**：停用 ASP.NET 版本標頭並移除 Server 標頭。"
    $MdContent += "```xml"
    $MdContent += "<system.web>"
    $MdContent += "  <httpRuntime enableVersionHeader=`"false`" />"
    $MdContent += "</system.web>"
    $MdContent += "<system.webServer>"
    $MdContent += "  <rewrite>"
    $MdContent += "    <outboundRules>"
    $MdContent += "      <rule name=`"Remove Server Header`">"
    $MdContent += "        <match serverVariable=`"RESPONSE_Server`" pattern=`".+`" />"
    $MdContent += "        <action type=`"Rewrite`" value=`"`" />"
    $MdContent += "      </rule>"
    $MdContent += "    </outboundRules>"
    $MdContent += "  </rewrite>"
    $MdContent += "</system.webServer>"
    $MdContent += "```"
    $MdContent += ""
}
if ($FailedTypes['TLS'] -or $FailedTypes['WEAK']) {
    $MdContent += "### 4. 舊版 TLS 或支援弱加密套件 (Weak Ciphers: CBC, SHA1)"
    $MdContent += "**風險**：使用過時的加密演算法或 TLS 版本，通訊內容可能被破解。"
    $MdContent += "**修正方式**："
    $MdContent += "Azure Web App 的 Cipher Suites 由平台管理。建議前往 **Azure Portal** > **App Service** > **TLS/SSL settings**，將 **Minimum TLS Version** 設為 **1.2**，這會自動停用大部分弱加密套件與舊版 TLS。"
    $MdContent += ""
}
if ($FailedTypes['TRACE']) {
    $MdContent += "### 5. 啟用 TRACE 方法"
    $MdContent += "**風險**：可能導致 Cross-Site Tracing (XST) 攻擊。"
    $MdContent += "**修正方式**：在 `"web.config`" 中加入請求篩選規則以禁用 TRACE。"
    $MdContent += "```xml"
    $MdContent += "<system.webServer>"
    $MdContent += "  <security>"
    $MdContent += "    <requestFiltering>"
    $MdContent += "      <verbs>"
    $MdContent += "        <add verb=`"TRACE`" allowed=`"false`" />"
    $MdContent += "      </verbs>"
    $MdContent += "    </requestFiltering>"
    $MdContent += "  </security>"
    $MdContent += "</system.webServer>"
    $MdContent += "```"
    $MdContent += ""
}
if ($FailedTypes['FILES']) {
    $MdContent += "### 6. 敏感檔案外洩 (.env / .git)"
    $MdContent += "**風險**：外洩環境變數、API Key 或原始碼資訊。"
    $MdContent += "**修正方式**：在 `"web.config`" 中利用 `"requestFiltering`" 封鎖。"
    $MdContent += "```xml"
    $MdContent += "<system.webServer>"
    $MdContent += "  <security>"
    $MdContent += "    <requestFiltering>"
    $MdContent += "      <hiddenSegments>"
    $MdContent += "        <add segment=`".env`" />"
    $MdContent += "        <add segment=`".git`" />"
    $MdContent += "      </hiddenSegments>"
    $MdContent += "    </requestFiltering>"
    $MdContent += "  </security>"
    $MdContent += "</system.webServer>"
    $MdContent += "```"
    $MdContent += ""
}

$MdContent | Out-File -FilePath $OutFile -Encoding UTF8
Write-Host "✅ 掃描完成！報告已儲存至: $OutFile"