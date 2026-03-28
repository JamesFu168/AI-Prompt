# GitHub Copilot Prompt for IIS Web.config Security Hardening

Use the prompt below in GitHub Copilot Chat when you want to update an IIS `Web.config` for an Angular SPA project with safe, low-risk security hardening.

```text
Please update this IIS `Web.config` for an Angular SPA project with safe, low-risk security hardening.

Requirements:
- Preserve existing Angular SPA routing and existing MIME type mappings
- Do not break static assets such as `.json`, `.svg`, `.woff`, `.woff2`, `.ttf`, `.eot`, `.webmanifest`
- Merge with existing config instead of replacing whole sections
- Do not add duplicate nodes or duplicate headers
- Do not add a strict `Content-Security-Policy` because it may break Angular; if needed, only mention `Content-Security-Policy-Report-Only` as a suggestion, but do not implement it

Please ensure the following settings exist:

1. Hide framework/server version info
- Under `<system.web>`:
  - `<httpRuntime enableVersionHeader="false" />`
- Under `<system.webServer><security><requestFiltering>`:
  - `removeServerHeader="true"`

2. Security headers under `<system.webServer><httpProtocol><customHeaders>`
Add if missing:
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer-when-downgrade`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `X-Permitted-Cross-Domain-Policies: none`

Also remove or avoid exposing:
- `X-Powered-By`

3. Block sensitive hidden folders/files
Under `<system.webServer><security><requestFiltering>`, add:
```xml
<hiddenSegments>
  <add segment=".env" />
  <add segment=".git" />
</hiddenSegments>
```

Also add a rewrite rule before the SPA rule to block hidden paths, while allowing `/.well-known`:
```xml
<rule name="Block Hidden Files" stopProcessing="true">
  <match url="^\\.((?!well-known).*)$" />
  <action type="CustomResponse" statusCode="403" statusReason="Forbidden" />
</rule>
```

4. Keep or add Angular SPA rewrite
If the request is not a physical file, rewrite to `/`.
Keep this rule after the hidden-file blocking rule.

5. Add HSTS only for HTTPS
Under `<system.webServer><rewrite><outboundRules>`, ensure there is a rule that adds:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
Only when HTTPS is on.

Important:
- Do not remove existing MIME mappings
- Do not overwrite existing `security`, `rewrite`, `rules`, `outboundRules`, or `customHeaders` sections if they already exist
- Integrate changes into the current structure
- Return the updated `Web.config`
```
