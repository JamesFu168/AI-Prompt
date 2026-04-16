param(
    [string]$TargetFile = "$PSScriptRoot\..\..\targets.txt",
    [string]$OutFile = "$PSScriptRoot\..\..\Security_Report.md",
    [ValidateSet("Simple", "Full")]
    [string]$ScanMode = "Simple"
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if (-not (Test-Path $TargetFile)) {
    Write-Host "❌ 找不到目標檔案: $TargetFile" -ForegroundColor Red
    exit
}

$Targets = Get-Content $TargetFile -Encoding UTF8 | Where-Object { $_ -and -not $_.StartsWith('#') }
$Results = @()
$FailedTypes = @{}
$NucleiFindings = @{}

$Pass = 'PASS'
$Fail = 'FAIL'
$NucleiPath = "$PSScriptRoot\..\..\nuclei.exe"

Write-Host "🚀 開始掃描任務 (模式: $ScanMode)..." -ForegroundColor Cyan

foreach ($Target in $Targets) {
    $CleanTarget = $Target.Trim()
    if (-not $CleanTarget) { continue }
    Write-Host "🔍 正在檢查: $CleanTarget"
    
    $Url = "https://$CleanTarget"
    
    # 1. 基本安全標頭檢查
    $Headers = curl.exe -s -I -L $Url 2>$null
    $Hsts = if ($Headers | Select-String 'Strict-Transport-Security') { $Pass } else { $FailedTypes['HSTS']=$true; $Fail }
    $Xfo = if ($Headers | Select-String 'X-Frame-Options') { $Pass } else { $FailedTypes['XFO']=$true; $Fail }
    $Xcto = if ($Headers | Select-String 'X-Content-Type-Options') { $Pass } else { $FailedTypes['XCTO']=$true; $Fail }
    $Leak = if ($Headers | Select-String 'X-AspNet-Version|X-Powered-By|^Server: (.+\d)') { $FailedTypes['LEAK']=$true; $Fail } else { $Pass }

    # 2. TLS 版本檢查
    $MinTLS = "1.2+"
    curl.exe --tlsv1.1 --tls-max 1.1 -I -s $Url | Out-Null
    if ($LASTEXITCODE -eq 0) { $MinTLS = "1.1(W)"; $FailedTypes['TLS']=$true }
    
    # 3. 弱加密套件檢查 (Nmap)
    $NmapOut = nmap --script ssl-enum-ciphers -p 443 $CleanTarget 2>$null
    $WF = @()
    if ($NmapOut | Select-String '_MD5') { $WF += 'MD5' }
    if ($NmapOut | Select-String '_CBC') { $WF += 'CBC' }
    if ($NmapOut | Select-String '_SHA ') { $WF += 'SHA1' }
    $Weak = if ($WF.Count -gt 0) { $FailedTypes['WEAK']=$true; "FAIL ($($WF -join ','))" } else { $Pass }

    # 4. 其他檢查 (TRACE, 敏感檔案)
    $Trace = if (curl.exe -X TRACE -I -s $Url | Select-String '200 OK') { $FailedTypes['TRACE']=$true; $Fail } else { $Pass }
    $EnvF = if (curl.exe -s -I "$Url/.env" | Select-String '200 OK') { 'ENV' } else { 'OK' }
    $GitF = if (curl.exe -s -I "$Url/.git/config" | Select-String '200 OK') { 'GIT' } else { 'OK' }
    $Files = if ($EnvF -eq 'OK' -and $GitF -eq 'OK') { $Pass } else { $FailedTypes['FILES']=$true; "FAIL ($EnvF/$GitF)" }

    # 5. Nuclei 廣度掃描 (僅在 Full 模式且 Nuclei 存在時執行)
    $NResult = "N/A"
    if ($ScanMode -eq "Full" -and (Test-Path $NucleiPath)) {
        Write-Host "🛡️  執行 Nuclei 掃描..." -ForegroundColor Gray
        $NucleiOutFile = "$env:TEMP\nuclei_$($CleanTarget)_$((Get-Date).Ticks).json"
        # 使用特定 tags 減少掃描時間並針對 Web App
        & $NucleiPath -target $Url -silent -nc -jsonl -o $NucleiOutFile -tags misconfig,exposure,panel,tech
        
        if (Test-Path $NucleiOutFile) {
            $Findings = Get-Content $NucleiOutFile | ForEach-Object { $_ | ConvertFrom-Json }
            $Crit = ($Findings | Where-Object { $_.info.severity -eq 'critical' }).Count
            $High = ($Findings | Where-Object { $_.info.severity -eq 'high' }).Count
            $Med = ($Findings | Where-Object { $_.info.severity -eq 'medium' }).Count
            $Low = ($Findings | Where-Object { $_.info.severity -eq 'low' }).Count
            $Info = ($Findings | Where-Object { $_.info.severity -eq 'info' }).Count
            
            if ($Crit + $High + $Med + $Low -gt 0) {
                $NResult = "FAIL (C:$Crit H:$High M:$Med L:$Low)"
                $FailedTypes['NUCLEI'] = $true
                $NucleiFindings[$CleanTarget] = $Findings
            } elseif ($Info -gt 0) {
                $NResult = "INFO ($Info)"
                # Info level doesn't trigger "FAIL" flag but we still want to show it if there's no other failure
                if (-not $NucleiFindings[$CleanTarget]) {
                    $NucleiFindings[$CleanTarget] = $Findings
                }
            } else {
                $NResult = "PASS"
            }
            Remove-Item $NucleiOutFile -Force
        } else {
            $NResult = "PASS"
        }
    } elseif ($ScanMode -eq "Full" -and -not (Test-Path $NucleiPath)) {
        Write-Host "⚠️  找不到 nuclei.exe，跳過 Nuclei 掃描。" -ForegroundColor Yellow
        $NResult = "N/A (Missing EXE)"
    } else {
        $NResult = "Skipped"
    }

    $Results += [PSCustomObject]@{
        T = $CleanTarget; H = $Hsts; X = "$Xfo / $Xcto"; L = $Leak
        TLS = $MinTLS; W = $Weak; TR = $Trace; F = $Files; N = $NResult
    }
}

$MdContent = @()
$MdContent += '# Web 伺服器安全掃描報告'
$MdContent += "掃描時間: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
$MdContent += ''
$MdContent += '| 目標 (Target) | HSTS | XFO / XCTO | 資訊外洩 | TLS 版本 | 弱加密 | TRACE | 敏感檔案 | Nuclei |'
$MdContent += '| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |'

foreach ($R in $Results) {
    $mH = if ($R.H -eq 'PASS') { '✅' } else { '❌' }
    $mX = $R.X.Replace('PASS','✅').Replace('FAIL','❌')
    $mL = if ($R.L -eq 'PASS') { '✅' } else { '❌' }
    $mTLS = if ($R.TLS -eq '1.2+') { '✅ 1.2+' } else { "❌ $($R.TLS)" }
    $mW = if ($R.W -eq 'PASS') { '✅' } else { $R.W.Replace('FAIL','❌') }
    $mTR = if ($R.TR -eq 'PASS') { '✅' } else { '❌' }
    $mF = if ($R.F -eq 'PASS') { '✅' } else { $R.F.Replace('FAIL','❌') }
    $mN = if ($R.N -eq 'PASS') { '✅' } elseif ($R.N -eq 'N/A') { '-' } elseif ($R.N -match 'INFO') { "ℹ️ $($R.N)" } else { "❌ $($R.N.Replace('FAIL ',''))" }

    $MdContent += "| $($R.T) | $mH | $mX | $mL | $mTLS | $mW | $mTR | $mF | $mN |"
}

if ($FailedTypes.Count -gt 0 -or $NucleiFindings.Count -gt 0) {
    $MdContent += ''
    $MdContent += '## ❌ 偵測到的弱點與修正建議'
    $MdContent += ''
    $MdContent += '針對 **Azure Web App (IIS)** 環境，請參考以下修復建議：'

    if ($FailedTypes['HSTS'] -or $FailedTypes['XFO'] -or $FailedTypes['XCTO']) {
        $MdContent += ''
        $MdContent += '### 1. 安全標頭缺失 (HSTS, XFO, XCTO)'
        $MdContent += '**修正方式**：在 `web.config` 的 `<system.webServer>` 節點中加入以下配置：'
        $MdContent += '```xml'
        $MdContent += '<httpProtocol>'
        $MdContent += '  <customHeaders>'
        $MdContent += '    <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />'
        $MdContent += '    <add name="X-Frame-Options" value="SAMEORIGIN" />'
        $MdContent += '    <add name="X-Content-Type-Options" value="nosniff" />'
        $MdContent += '  </customHeaders>'
        $MdContent += '</httpProtocol>'
        $MdContent += '```'
    }
    
    if ($FailedTypes['LEAK']) {
        $MdContent += ''
        $MdContent += '### 2. 資訊外洩 (Server, X-Powered-By, X-AspNet-Version)'
        $MdContent += '**修正方式**：'
        $MdContent += '- 隱藏 **X-Powered-By**: 在 `web.config` 的 `<customHeaders>` 中加入 `<remove name="X-Powered-By" />`。'
        $MdContent += '- 隱藏 **X-AspNet-Version**: 在 `<system.web>` 節點中設定 `<httpRuntime enableVersionHeader="false" />`。'
        $MdContent += '- 隱藏 **Server**: 在 `web.config` 加入 `<security><requestFiltering removeServerHeader="true" /></security>`。'
    }

    if ($FailedTypes['TLS'] -or $FailedTypes['WEAK']) {
        $MdContent += ''
        $MdContent += '### 3. 弱加密套件或過舊 TLS 版本'
        $MdContent += '**建議**：在 Azure Portal 的 "TLS/SSL settings" 中將 "Minimum TLS Version" 設定為 **1.2**。'
    }
    
    if ($FailedTypes['FILES']) {
        $MdContent += ''
        $MdContent += '### 4. 敏感檔案外洩 (.env, .git)'
        $MdContent += '**修正方式**：在 `web.config` 中禁止存取特定路徑：'
        $MdContent += '```xml'
        $MdContent += '<security><requestFiltering><denyUrlSequences><add sequence=".env" /><add sequence=".git" /></denyUrlSequences></requestFiltering></security>'
        $MdContent += '```'
    }

    if ($NucleiFindings.Count -gt 0) {
        $MdContent += ''
        $MdContent += '### 5. Nuclei 偵測到的其他弱點與資訊'
        $MdContent += '| 目標 | 風險程度 | 弱點名稱 | 描述 |'
        $MdContent += '| :--- | :--- | :--- | :--- |'
        foreach ($T in $NucleiFindings.Keys) {
            foreach ($F in $NucleiFindings[$T]) {
                $Severity = $F.info.severity.ToUpper()
                $mSev = if ($Severity -eq 'CRITICAL') { '🔴 CRITICAL' } elseif ($Severity -eq 'HIGH') { '🟠 HIGH' } elseif ($Severity -eq 'MEDIUM') { '🟠 MEDIUM' } elseif ($Severity -eq 'LOW') { '🟡 LOW' } else { "ℹ️ $Severity" }
                $CleanDesc = if ($F.info.description) { $F.info.description -replace '[\r\n]+', ' ' } else { '-' }
                $MdContent += "| $T | $mSev | $($F.info.name) | $CleanDesc |"
            }
        }
    }
}

$FinalOutput = $MdContent -join "`r`n"
[System.IO.File]::WriteAllText($OutFile, $FinalOutput, [System.Text.Encoding]::UTF8)

Write-Host ""
Write-Host "✅ 掃描完成！報告已儲存至: $OutFile" -ForegroundColor Green

