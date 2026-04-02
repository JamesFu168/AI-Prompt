# Web 伺服器安全掃描報告
掃描時間: 2026-03-31 05:50:21

| 目標 (Target) | HSTS | XFO / XCTO | 資訊外洩 | TLS 版本 | 弱加密 | TRACE | 敏感檔案 | Nuclei |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| eshclouds-lawking-developer.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (8) |
| eshclouds-lawking-api-developer.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (12) |
| eshclouds-legal-api-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |
| eshclouds-product-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ✅ |
| eshclouds-product-api-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (12) |
| eshclouds-chem-api-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |
| esh-action-web-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |
| esh-action-api-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |
| esh-carbon-web-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (10) |
| esh-carbon-api-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |
| eshclouds-license-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |
| eshclouds-license-api-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (8) |
| eshclouds-permit-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |
| eshclouds-permit-new-api-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (13) |
| eshclouds-risk-next-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |
| eshclouds-risk-next-api-develop.azurewebsites.net | ❌ | ❌ / ❌ | ❌ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (15) |
| eshclouds-indicator-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (8) |
| eshclouds-indicator-api-develop.azurewebsites.net | ✅ | ✅ / ✅ | ✅ | ✅ 1.2+ | ✅ | ✅ | ✅ | ℹ️ INFO (9) |

## ❌ 偵測到的弱點與修正建議

針對 **Azure Web App (IIS)** 環境，請參考以下修復建議：

### 1. 安全標頭缺失 (HSTS, XFO, XCTO)
**修正方式**：在 `web.config` 的 `<system.webServer>` 節點中加入以下配置：
```xml
<httpProtocol>
  <customHeaders>
    <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
    <add name="X-Frame-Options" value="SAMEORIGIN" />
    <add name="X-Content-Type-Options" value="nosniff" />
  </customHeaders>
</httpProtocol>
```

### 2. 資訊外洩 (Server, X-Powered-By, X-AspNet-Version)
**修正方式**：
- 隱藏 **X-Powered-By**: 在 `web.config` 的 `<customHeaders>` 中加入 `<remove name="X-Powered-By" />`。
- 隱藏 **X-AspNet-Version**: 在 `<system.web>` 節點中設定 `<httpRuntime enableVersionHeader="false" />`。
- 隱藏 **Server**: 在 `web.config` 加入 `<security><requestFiltering removeServerHeader="true" /></security>`。

### 5. Nuclei 偵測到的其他弱點與資訊
| 目標 | 風險程度 | 弱點名稱 | 描述 |
| :--- | :--- | :--- | :--- |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | Missing Subresource Integrity | Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.  |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | XSS-Protection Header - Cross-Site Scripting | Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability. |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | Missing Cookie SameSite Strict | Identified cookies that lacked the samesite=strict attribute, which prevented enforcement of restrictions on cross-domain cookie transmission.  |
| esh-carbon-web-develop.azurewebsites.net | ℹ️ INFO | Wappalyzer Technology Detection | - |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | Public Swagger API - Detect | Public Swagger API was detected.  |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | Public Swagger API - Detect | Public Swagger API was detected.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-carbon-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-developer.azurewebsites.net | ℹ️ INFO | XSS-Protection Header - Cross-Site Scripting | Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability. |
| eshclouds-lawking-developer.azurewebsites.net | ℹ️ INFO | Missing Subresource Integrity | Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.  |
| eshclouds-lawking-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | Missing Subresource Integrity | Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | Missing Cookie SameSite Strict | Identified cookies that lacked the samesite=strict attribute, which prevented enforcement of restrictions on cross-domain cookie transmission.  |
| esh-action-web-develop.azurewebsites.net | ℹ️ INFO | XSS-Protection Header - Cross-Site Scripting | Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability. |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | ASP.NET Debugging Enabled | - |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | WAF Detection | A web application firewall was detected. |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | WAF Detection | A web application firewall was detected. |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-lawking-api-developer.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | Public Swagger API - Detect | Public Swagger API was detected.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-chem-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | Public Swagger API - Detect | Public Swagger API was detected.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| esh-action-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | Public Swagger API - Detect | Public Swagger API was detected.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-legal-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | XSS-Protection Header - Cross-Site Scripting | Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability. |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | Wappalyzer Technology Detection | - |
| eshclouds-risk-next-develop.azurewebsites.net | ℹ️ INFO | Missing Subresource Integrity | Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.  |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | Wappalyzer Technology Detection | - |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | XSS-Protection Header - Cross-Site Scripting | Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability. |
| eshclouds-permit-develop.azurewebsites.net | ℹ️ INFO | Missing Subresource Integrity | Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.  |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | Missing Subresource Integrity | Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.  |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | XSS-Protection Header - Cross-Site Scripting | Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability. |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-license-develop.azurewebsites.net | ℹ️ INFO | Wappalyzer Technology Detection | - |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | FingerprintHub Technology Fingerprint | FingerprintHub Technology Fingerprint tests run in nuclei. |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-permit-new-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | Public Swagger API - Detect | Public Swagger API was detected.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | WAF Detection | A web application firewall was detected. |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | Microsoft IIS version detect | Some Microsoft IIS servers have the version on the response header. Useful when you need to find specific CVEs on your targets. |
| eshclouds-risk-next-api-develop.azurewebsites.net | ℹ️ INFO | Wappalyzer Technology Detection | - |
| eshclouds-indicator-develop.azurewebsites.net | ℹ️ INFO | XSS-Protection Header - Cross-Site Scripting | Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability. |
| eshclouds-indicator-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-indicator-develop.azurewebsites.net | ℹ️ INFO | Missing Subresource Integrity | Checks if external script and stylesheet tags in the HTML response are missing the Subresource Integrity (SRI) attribute.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | Public Swagger API - Detect | Public Swagger API was detected.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | WAF Detection | A web application firewall was detected. |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | AspNetMvc Version - Detect | Detects version disclosed via 'X-AspNetMvc-Version' header.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |
| eshclouds-product-api-develop.azurewebsites.net | ℹ️ INFO | HTTP Missing Security Headers | This template searches for missing HTTP security headers. The impact of these missing headers can vary.  |